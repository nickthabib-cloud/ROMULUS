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
AI investigating agent (planned) ─► orient ─► hypotheses, typed pivots ─► AI triage ─► AI assessment
                            │      (triage: a labelled, promote-only view over the surfaced finding groups, never
                            │       the report order; its verdicts reach the assessment, whose narrative is checked
                            │       against the Reported set, confirmed findings and those verdicts; triage keeps its
                            │       own budget, so the phase can run up to AGENT_TRIAGE_MAX_WALL_SECONDS longer than
                            │       AGENT_MAX_WALL_SECONDS)
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

## Mention sweep

Records the sweep reads but no normalizer turns into a typed event are scanned for mentions (`hunt.mentions`). These are records of a dataset or event class no normalizer reads, text in no recognized format or too long to parse, and records a normalizer failed on. `normalize_hits(unread=...)` lists them; a duplicate copy of a record that was read is never listed. Records the sweep's dataset and class filters never fetch are not scanned either: the coverage section's not-assessed list names them.

- **What is read.** One typed text field per record (`message`, else `event.original`), never a serialized record, up to 8,192 characters. Longer lines are counted with the characters not scanned.
- **Patterns.** `content.mention_patterns` loads `content/mentions/*.yaml` (or `ROMULUS_MENTION_DIR`). Each pattern has an id, title, strength, telemetry classes, source and licence, rationale, and positive and negative examples. A file is validated strictly as a whole: an unknown key, a duplicate id, an expression outside the admitted subset, or an example that does not behave as stated refuses the whole file, and coverage names it. A literal is at least three characters. An anchored expression must start with `^` or a literal prefix of at least four characters. It may not use back references, lookaround, inline flags, nested repeats or alternation under a repeat, and its backtracking product must stay within two unbounded repeats.
- **Matcher** (`evidence.mention_match`). A gate regex anchors each literal at its rarest character, so the engine skips at C speed over positions that anchor nothing. On a line the gate passes, an Aho-Corasick automaton lists every literal. An anchored expression runs only where its literal prefix occurs (at most four places per line), over a window of 512 characters; one with an end anchor runs only where the line's real end is inside that window. A line where the prefix occurred more often than it is tried, or where the window ended before the line did and the expression could have matched past it, is counted as not ruled out.
- **Pool.** Matches are grouped by (pattern, host, normalized line) in a private SQLite stage. The stage is a yielding store of the hunt's state budget: it has no floor and gives way before any detection store would refuse a key. The pool is bounded per pattern, per host and per hunt. Past a cap a group is not kept, but its lines are still counted, so remainders are exact. The stage remembers a bounded number of such groups; past that bound the count of groups not kept is a lower bound, and coverage says so. At the host and hunt caps a stronger pattern's group takes a weaker one's place. Pool order is pattern strength, then rarity (the pattern's distinct hosts, then its matching lines), then first time. At the end of the sweep the pool replaces the hunt's stored pool in one transaction (`mention`, `mention_scan`). Each mention's first record is kept on the raw-record path (`agent_raw_record`, origin `mention_sweep`), cleaned, redacted and bounded; these rows never count toward the agent's raw-record cap.
- **Lane.** `mention` is a lane of its own between context and lead, stored outside the findings table. Ranking, triage, expansion, entities, incidents and hypothesis decisions never read it. The report manifest carries the pool's coverage and its top mentions under `mentions`; Markdown, DOCX, the web *Mentions* tab and the agent's dossier and `list_mentions` tool show them labelled as mentions. No alias is issued for a mention, so the agent cannot cite one: it corroborates a mention with typed evidence and cites that.
- **Coverage.** The pool's status is `complete`, `partial` (a refused pattern file, a line cut at the bound, a line not ruled out, a cap reached, a stage write refused, or a stopped sweep, each named with its counts) or `not_scanned` (no patterns loaded). It never reads as "no mentions". The pool's coverage does not change the detection result.

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

Service authentication, resolver requests, proxy requests, firewall packets, IDS alert lines (Suricata `fast.log`),
scheduler observations and account changes use the existing `auth`, `dns_query`, `http_access`, `net_flow`,
`net_alert`, `process_observed`, `service_change` and `account_change` families. A `fast.log` alert carries the
fields an EVE alert does except its flow id, application protocol and signature metadata; its community ID is
computed from its 5-tuple. dnsmasq lines are typed one at a time: with `log-queries=extra` each line keeps its query
serial and requester, and lines are never joined. A question the resolver logged names its host as the server, a
reply line in `extra` mode names the requester as its client, and the forwarded line's requester is never read as a
client of that upstream question, so one lookup is counted once. dnsmasq DHCP acknowledgements are
`address_assignment` records. OpenVPN's own log file is read in both of its time formats. Because other programs
write the same ISO time and the same words, an ISO-stamped line, and any line known only by an untyped OpenVPN phrase,
is read as OpenVPN only when the record's file path, dataset or module names an OpenVPN log. A resolver log's host
server is the host its line header names, else the host that shipped it, and the claim says which. Certificate checks, TLS
handshake failures and packet authentication failures are typed with their own authentication phase, never as password
decisions. Recognized lines of these programs that carry no event are counted with a named reason. Authentication sessions are distinguished from authentication decisions. Firewall
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

A sample decides only what the sweep asks for, never what it read. On a Linux host target the sweep counts each
dataset's records in the hunt window before retrieval and tallies what its partitions actually return (a bounded
number of names per target). A selected dataset whose window records were not all returned is reported with the
shortfall, makes the hunt partial and leaves the rules reading its families partial on that target; where either
count is unavailable the dataset is reported as not counted. Window datasets the profile inventory never listed are
reported with their window counts, and a selected text dataset with records in the index but none in the window is
named, since records indexed when they were shipped fall outside the window they describe. When the window cannot be
counted by dataset (a failed or partial count, a bucket cap, or a dataset field that cannot be aggregated), the
reconciliation is reported as not performed, with its reason, and the hunt is partial. A mapped field whose index or
doc values are switched off carries that in its profiled type: no predicate searches a field that is not indexed,
and no aggregation reads one without doc values.

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

## Hunt controls: agent budgets, extensions, stop

`agent/hunt_budget.py` and `hunt/controls.py`.

**Agent budget.**
- A hunt pins its AI agent budget in its manifest (`ai_agent.budgets`, schema `agent-budget@1`) when it is created.
  - The budget is a profile (quick, standard or deep, as multiples of the `.env` limits) plus optional per-limit values.
  - Its limits are model calls, tokens, wall clock, cost, source queries, hypotheses, sessions per hypothesis and tool calls per session. The triage pass's limits are pinned beside them.
- The agent phase, its triage pass, `romulus triage`, the dossier's remaining-budget page and every resume read the pinned budget plus the hunt's extensions (`hunt_budget.hunt_settings`), never the live settings.
- A hunt created before budgets were pinned keeps the limits its manifest recorded. It reads the others from the settings and names them on its Run tab.
- Choices and extensions stay within the site ceiling (`AGENT_BUDGET_CEILING_MULTIPLIER` times each standard limit, within the limit's own maximum). Only a lead may go above it.
  - The web checks the role against the database and hands the checked choice to the hunt process as a single-use grant.
  - On the command line, `--user` authenticates a lead with its password.

**Extensions.**
- An extension is a row recorded with who added it, when, and the amounts.
- New limit = pinned + every extension. Spending persists, so the agent continues from what it has already used.
- A running agent reads the raised call, token, time and cost limits within 15 s, and raised source-query shares from its next session.
- An agent run that ended partial on a limit becomes resumable once budget is added after it ended. `hunt resume --agent-only` (the web starts it after an extension) continues from the persisted hypotheses, sessions and spend, and never runs a deterministic stage again.

**Stop.**
- A stop request is a row (scope `hunt` or `agent`, who, when).
- The run reads it through a cached lookup (at most every 2 s) at these safe points:
  - before each sweep source and partition;
  - between the post-sweep stages;
  - before each expansion link;
  - in the agent, before every model call, before every read tool call, while waiting for budget, between rounds, and before every triage call.

The packet, baseline, site-network check and ranking stages check only at their boundaries. A stop that arrives while one runs takes effect when its current step ends, or by a force stop.

What happens depends on where the stop arrives:
- **During the sweep.** The sweep closes its stage and finalizes nothing, since an aggregate over part of the window could report what the rest would contradict. Its summary says it did not finish; the partitions it had not read stay planned; the hunt ends partial; and every whole-window answer is narrowed. A resume runs the sweep again: its writes are idempotent, and aggregates must read every partition.
- **After the sweep.** The stages that did not run record no summary, and the stop reason names them. Every rule a skipped stage owns reads partial, never "no data in scope" or complete: each baseline spec's whole-window cell, and the packet rules' and the indicator rule's URL and SHA256 cells on each Arkime session target. The stage's own cells replace these when a resume runs it. Expansion leaves its unfinished anchors pending, so a resume works them.
- **In the agent.** The agent makes no further model call (no triage pass, no assessment), keeps what it stored, and ends partial with `stopped_by_analyst`.

A resume clears the requests made before it claimed the hunt; one made after the claim is for the resumed run. A request the run never reached a safe point for is closed as unapplied. A hunt stop that reaches the run only in its agent phase stops the agent; detection that completed within scope stays complete.

**Force stop.**
- Every worker records its pid, a start marker (the kernel's process start time and boot id), its host and the process group it leads. A worker the web starts leads its own session; one started from a script without a terminal moves into a group of its own; one run at a terminal stays in its job, and only its pid is signalled.
- After the grace period (`ROMULUS_HUNT_STOP_GRACE_SECONDS`), a lead may force-stop. ROMULUS signals the recorded process only on its own host, only while the pid still has that start marker and runs ROMULUS, and never a reused pid.
- It then leaves the hunt partial and its agent interrupted, in one transaction. A sweep that had not finished is marked stopped, so a resume runs it again.
- Hosts without `/proc` cannot verify a process, so they refuse a force stop.

## Agent working context

`agent/context.py`. An agent session's prompt is kept bounded however much it reads:
- Every tool result is stored whole for the session (in memory, overflowing to a temporary file), with configured secrets removed, under a handle (`R<n>-<session tag>`; handles are per session). `get_result` re-reads it in pages, each within the result cap as shown, without a source query. Re-reads have their own allowance (the session's reads); once it is spent the model is told, and a reply that makes only refused calls ends the session capped.
- A result larger than one page (at most 10,000 estimated tokens, or 5 % of a smaller context) enters the conversation as its envelope (status, counts, what to read next, the aliases it issued) and its first page.
- Once the results the model has already been sent, older than the latest four, reach 32,000 estimated tokens (at most a quarter of a smaller context), all of them are replaced at once by stubs: the tool, its arguments, status, counts, negative statement, cursor and next chunk, and every alias the result issued (aliases stay issued, so they stay citable). A stub carries no telemetry text and never changes once written. The model's own turns and the results of the tools that record its work are never compacted.
- Between compactions the conversation only grows at its end, so the provider's prompt cache keeps reading its prefix. The call after a compaction is reserved against the budget as written to the cache.
- A compaction is the session's one edit of what it already sent. Anthropic binds each signed thinking block to the conversation it was produced in and refuses a replayed block whose earlier conversation changed, so every model turn after the first stubbed result goes out without its thinking from then on (text and tool calls stay). That is a run of blocks removed from the end, which the API accepts; turns before the edit keep their thinking, and turns produced after the compaction keep theirs until the next one. If the API still refuses replayed thinking, the session removes the thinking from every earlier turn and retries once; a second refusal ends it as `reasoning_binding_rejected`. The OpenAI Responses adapter replays its encrypted reasoning items unchanged: OpenAI documents no such binding for them, and the API requires each function call's reasoning item to stay with it.
- Configured secrets are weak or strong by one rule (`config.weak_secret_names`, which doctor's `secrets.strength` warning also uses): short, single-class, low-entropy, or a word of the product's own text. The rule decides only what a secret in a model reply does to the session; every secret's text is redacted wherever it appears. When a model reply arrives, every weak secret's text in it is replaced before the reply is validated, run, stored, shown or appended: in its text, parsed answer, tool-call names and arguments (re-serialised so the raw and parsed forms agree), readable reasoning summaries, and the provider state its turn replays from. An Anthropic turn that held one goes on without its signed thinking, which cannot be edited (a run removed from the end, as above). The session continues; the replacements count in the call's `output_redactions` and each setting gets an `agent.weak_secret_redacted` audit row (names and counts only). A reply holding a strong secret's text is left as it is: replaying it raises `SecretGuardTripped`, and the session ends as `secret_guard`.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` emits validated typed pivots without importing any module under `romulus.sources`. The hunt-layer pivot executor converts them to `SearchIntent`s and owns source access. This includes the agent's typed search (`search_events`): the agent validates its shape (scope, operations, value counts and lengths), and the executor checks each condition against each target's field contract, compiles it, and refuses or lists as not evaluated whatever a target cannot take. The agent learns what it can search from `list_search_fields`, which the executor answers from the hunt's field contracts (the typed fields, with the operations and scopes the planner applies) and stored source profiles (each source's own fields, and an Arkime viewer's expression fields read when the hunt was profiled), without any source query. The agent may also write its own query of one hunt source (`query_source`): a Query DSL query with optional aggregations, sort and size for an index, or an expression for an Arkime viewer. The agent package only checks its shape; `sources.agent_query` is the boundary. It accepts only allowlisted query clauses and aggregation types, each with its allowed keys, with every capped number a JSON integer, and refuses at any depth anything that runs code, reads another index or reads outside the query (scripts, runtime fields, percolation, wrapped queries, terms lookups, global or join aggregations, empty-bucket term lists). Lucene's own safety limits stay in force, since a pattern's automaton is built on each data node before any timeout applies: `max_determinized_states` is never accepted, expansion counts are at most 100, rewrites are constant-score only, and a regular expression, wildcard pattern, terms include or exclude, or query string holding a regular expression is at most 1,000 characters; an Arkime expression holds at most two regular expressions of at most 200 characters. Field names and labels must match a strict name pattern; every structural and option key is also checked against a list of forbidden constructs. A top-N aggregation with other values left out, and a source's own time gaps, make the answer partial. It builds the body itself: the agent's query is one `bool.filter` clause beside the hunt window's range on the source's time field, with fixed size, timeout, terminate_after and total-count caps, and aggregations bounded by size and by the product of their bucket counts. The source is looked up by exact name in the hunt's own source table, and the request goes through the existing client and its request allowlist (`POST /<index>/_search`; for Arkime, the viewer's `GET /api/sessions`, whose session ids are then read from the hunt's session index inside the window). Each query spends the agent's source-query budget and shares; a repeat spends nothing; a query the source rejects is returned as its bounded, redacted error text and never sent again. Returned records that a normalizer reads are stored as evidence and pass through direct detection; rows and aggregations are kept as a bounded, redacted preview. A preview row no normalizer reads is kept, up to a per-hunt cap, as a raw record (`evidence.raw_citation`, `Q` aliases): bounded, redacted text with its source reference, time, digest and provenance, citable only as a mention and labelled everywhere as not normalized. Aggregations are not citable. Zero hits is never an absence.
- `baseline` defines source-neutral typed keys and imports neither `hunt` orchestration nor `sources` adapters.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
