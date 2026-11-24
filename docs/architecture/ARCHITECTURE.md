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
AI investigating agent (optional) ─► orient ─► hypotheses, typed pivots ─► AI triage ─► AI assessment
                            │      (triage: a labelled, promote-only view over the surfaced finding groups, never
                            │       the report order; its verdicts reach the assessment, whose narrative is checked
                            │       against the Reported set, confirmed findings and those verdicts; triage keeps its
                            │       own budget, so the phase can run up to AGENT_TRIAGE_MAX_WALL_SECONDS longer than
                            │       AGENT_MAX_WALL_SECONDS)
                            │
report ─► ReportManifest ─► JSON | Markdown | executive DOCX | indicator export (STIX 2.1, CSV) | web (findings,
                              incidents, narratives, timeline)
```

Coverage cells are written at every stage that can lose information (compile, execute, ingest, normalize, evaluate), so the report can say exactly what was and wasn't assessed.

## Evidence ranking

A finding's lane is its rule's own estimate. The report's headline comes instead from the structure of the evidence in the hunt itself (`decide/rank.py` holds the model, `hunt/rank.py` runs it, `store/ranks.py` stages and stores it):

- **Confirmed** findings (lane `urgent`) are always reported on their own.
- Every other `high` or `lead` finding is in the **ranked pool**. That includes a cited positive whose admission is incomplete (a predicate field without lineage, or no affected entity): it is kept as a lead at medium severity at most, with a note naming what is missing, so a rule's positive never drops out of sight. Context and suppressed records stay outside the pool as supporting records.
- **Entities.** A host-telemetry finding counts toward its host and account. An account named with a domain or by SID is one entity across hosts; a bare local name is qualified by its host. A network-telemetry finding counts toward its endpoints: internal addresses first, at most two. An internal endpoint is the host whose own telemetry owns that address unambiguously in the hunt, else the address; an external endpoint is an `ip` entity. A network sensor is never an entity, and well-known principals that exist on every host (SYSTEM, root) are not entities. A finding with none of these is `unattributed`: it is ranked on its own prior and listed.
- **Entity evidence**, from the hunt's deterministic findings only: confirmed findings (U), ATT&CK tactic breadth (T: a maximum matching of rules to the tactics each maps to, so each rule adds at most one tactic; tactics come from the vendored ATT&CK data), distinct rules (R), and pairs of rules that fire within an hour of each other (C, capped). A rule whose confirmed and pool findings fall on at least half of the hunt's hosts with any deterministic candidate (and at least three) over at least half of the window is *recurring fleet-wide*: it counts toward no entity, and its findings rank lower but are never removed. A short burst across the fleet is not penalized.
- **Entity score** = 40·U + 10·T + 5·R + 3·C + the strongest rule prior among its findings. **Finding rank** = its best entity's score + its own rule prior, less 30 for a recurring fleet-wide rule; ties break on time, then id. In the final order, a `lead` past the first two findings of its rule listed under one entity inherits half that entity's score: it ranks behind findings of entities with comparable evidence but stays above weaker entities', so many leads of one routine rule on a busy host never fill the top of the order. Confirmed and `high` findings always inherit in full, and lanes, sections and the Reported set do not change. Every score carries its reasons.
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

## Executive report (DOCX)

`report/executive.py` formats the report manifest as a Word document for leadership; `report/ooxml.py` holds the styled base template (headings with outline levels, banner, callouts, captions, the report table style) and writes the package with the standard library only. The classification banner is in the header and footer of every page and opens and closes the body. Sections: title page, bottom line, hunt scope, key findings (confirmed or urgent first, on their own), the attack path, the AI assessment and the AI triage view (each labelled as AI output; a hunt without the agent says so), the mention pool (labelled as mentions, never findings; text flagged as possible prompt injection is withheld), recommendations, coverage limitations (every gap, not-assessed row and note), and an index of every finding with its report section and lane.

- **Bounded, never lossy.** Sections that show a selection (finding details, mentions, the picture) state how many items they leave out and where they are; the finding index lists every finding. The body is streamed into its package part.
- **Attack-path picture.** `report/attack_path.py` draws the strongest incidents (at most 8 rows of 6 steps) as a PNG: boxes numbered by their finding-index row and coloured by lane, solid arrows for observed links, dashed arrows tagged `H` for every other strength (a hypothesis). It holds no telemetry, only numbers, times and legend words; names and claims stay in document text beside it. Counts of incidents, findings and links not drawn are stated under it.
- **Inert text.** Manifest text is written only as escaped text nodes. XML-forbidden and zero-width or formatting characters are removed, and direction controls (such as a right-to-left override) are shown by name, so a disguised file name stays evident. Manifest text never reaches an attribute, a relationship, a style or a field; attribute values are checked colours and identifiers. The output is reproducible: the same manifest gives the same document parts and picture pixels (compressed bytes can differ between zlib builds).
- **Checks.** Tests read the document back against the manifest (finding ids and lanes, counts, coverage rows, mention totals, overflow notes, a 5,000-finding manifest), check the package structure, and convert it to PDF with LibreOffice where it is installed.

## Recommendations and indicator export

`report/recommendations.py` builds the manifest's `recommendations` from the reportable findings. A finding's techniques are its own validated ATT&CK context when it carries one, else its rule's; each is resolved in the pinned ATT&CK release (Enterprise or ICS, by the rule's domain first; a revoked id follows its replacement) and mapped through the release's `mitigates` relationships (`catalog/mitigations.py`, read offline from the vendored bundles and checked against their pinned digests). A sub-technique with no mitigation of its own takes its parent's, and says so. One recommendation is made per mitigation, with the techniques, findings and entities it addresses and the checks their rules recommend; lists are bounded and every count is exact. Priority comes from the strongest finding addressed: immediate for an urgent finding, a high finding of critical or high severity, or one an analyst confirmed malicious; near-term for any other high finding or a critical or high lead; longer-term otherwise. An AI agent finding raises a recommendation to near-term at most unless an analyst confirmed it, and one an analyst marked benign or expected raises it to longer-term at most. A finding with no technique, or with no actionable mitigation (ATT&CK's Do Not Mitigate, Pre-compromise and Mitigation Limited entries, and for ICS any mitigation that would probe OT devices, are not actions), gets a triage recommendation at its own priority, so no finding is left out. Every recommendation from ATT&CK for ICS carries a passive-only caveat: nothing in it is an instruction to scan or query control devices. A finding whose claim is a mention drives no recommendation and is listed apart.

`report/iocs.py` exports the values the reportable findings rest on: their typed entities, their allowlisted predicate fields, the allowlisted typed fields of the events they cite as their subject (not records cited only as context, such as a lineage ancestor), and a fleet finding's members from its host appendix (addresses with their direction, DNS, HTTP, URL and TLS server names, URLs, file and image hashes, file and executable paths, accounts, JA3/JA4/HASSH and certificate fingerprints). Nothing comes from raw text, claims, notes, mentions or model prose, and a mention finding contributes nothing. Every value passes credential masking and validation first; a value holding a credential (including URL forms whose path or query is the credential: chat webhooks, bot tokens, access keys, OAuth codes) or a configured secret is withheld and counted under one reason, so the export never says which value a configured secret is part of, and is never exported in part. A strong configured secret is found anywhere in a value; a weak one (short, low-entropy or a common word) is not looked for, since the other renderers print the same values and withholding them would only point at it. The export-only URL checks (exact credential parameter names, credential URL paths) leave indicator import and the sweep's URL matching unchanged. A port written with a host name is exported apart from the name. Addresses are marked internal or external by the hunt's recorded site networks (unknown when that record is unreadable), the hunt's own hosts are internal, and names and paths are not addresses. The rows are aggregated in a scratch SQLite file (`report/spill.py`), so memory stays bounded whatever the hunt's size. The manifest's `indicators` holds the exact counts by kind and scope, what was withheld, a preview and a content digest. `report.bundle.write_reports` writes `<revision>-iocs.csv` (one row per value, finding, role, field and port, with the finding's lane, provenance and analyst status; every cell guarded against formula injection) and `<revision>-iocs-stix.json` (a STIX 2.1 bundle: SCOs with deterministic ids, one `observed-data` per value with its findings, lanes and scope, and a `report` referencing all of them; host names and fingerprints use `x-romulus-*` custom observables) beside the other files. They are written streaming, checked against the manifest's digest and counts, and replace earlier files only once complete; a failure leaves a note beside the revision and costs no other output.

## Mention sweep

Text no rule reads is scanned for mentions (`hunt.mentions`):
- records the sweep reads that no normalizer turns into a typed event: a dataset or event class no normalizer reads, text in no recognized format or too long to parse, a record a normalizer failed on, and a Windows record on a network target (`normalize_hits(unread=...)`; a duplicate copy of a record that was read, a journald copy of an audit record among them, is never listed);
- of raw audit records, a group that made no typed event (every record), a record that does not parse, and the process title of a group without an EXECVE record (the command line of the process behind a socket, file, module or administrative call, which no typed field reads; an exec group's title is the command line its event already reads);
- the records outside the sweep's own selection (`hunt.mention_residue`). After a target's partitions they are counted exactly, with the very query the sweep compiled negated (`SearchIntent.excluding`), so the two reads together see every record of the window once, then streamed page by page through a point in time and offered whole, to the end of that point in time within the budget (a record indexed after the count is read; a point-in-time total that differs from the count makes the pool partial). Nothing there is normalized or evaluated. A per-target budget (`ROMULUS_MENTION_RESIDUE_RECORDS`) bounds the read: past it the smallest datasets (or channels, providers, modules, whichever the target can count and search exactly) are read whole first and the rest share what is left, else the earliest records by time; every record not read is counted per key.

- **What is read** (`hunt.mention_fields`). Never a serialized record: a documented selection of each record's free-text fields by its family, each field scanned as its own text. Text records: `message`, NXLog's `Message` or a Windows record's rendered message (else a plain-text `event.original`), with the ECS and Beats free-text fields (command lines, process titles and paths, URLs, user agents, referrers, DNS names, file paths, script blocks, mail subjects) and a Windows record's free-text event data (`CommandLine`, `ScriptBlockText`, `TargetFilename`, `QueryName`, and the like). Raw audit lines: the decoded `proctitle`, `cmd`, `exe`, `comm`, `data`, `name`, `path` and an EXECVE record's arguments, never the hex. JSON in `event.original` or in `message` (never scanned as one serialized line): a journal record's `MESSAGE`, `_CMDLINE`, `_EXE`, `_COMM` and `SYSLOG_IDENTIFIER`; Suricata EVE by event type and Zeek by log, from their format documentation (sensor rule text, packet payloads and secrets are left out); an ECS-shaped document's ECS fields. A Windows event exported as XML is read by its rendered message and event data (bounded, never a document declaring a DTD or entity). Credentials: a Zeek or EVE object goes through its producer's scrubber whatever recognised it, and the mention keeps that scrubbed record; a credential command's argument, HTTP/2 credential headers and message bodies are never selected, and every selected text loses URI userinfo and SIP passwords. A family record holding none of its fields has no free text and is counted, not a gap; an EVE record whose packet payload or body is not read, and a list or nesting cut at its bound, are counted as scanned in part; an EVE type, Zeek log or ECS document outside the tables is scanned by the tables' fields and counted as scanned in part; a JSON record of no family, a JSON array and an XML document are not scanned and are counted. At most 32 texts per record; the literal pass reads up to 256 KiB across a record's texts; the rest is counted, with the hosts and records it came from.
- **Patterns.** `content.mention_patterns` loads `content/mentions/*.yaml` (or the settings' `ROMULUS_MENTION_DIR`); a hunt pins the set's digest and each file's digest when it is created, and its sweep names every file that differs. Each pattern has an id, title, strength, telemetry classes, source and licence, rationale, and positive and negative examples. Each pattern is validated strictly: an unknown key, a duplicate id, an expression outside the admitted subset, or an example that does not behave as stated refuses that pattern alone, and the rest of its file still runs. A file that cannot be read as a pattern list is refused whole. Coverage and the hunt's pinned pattern-set record name every refused pattern and file with why, and any refusal makes the pool partial. Doctor's `mentions.patterns` check loads the same set and reports the patterns and files loaded; an empty or missing directory, or any refusal, is a warning. Ids are `mention.<words_joined_by_underscores>`; `telemetry: [any]` stands alone. A literal (at least three characters) matches as a substring under the pattern's case flag. An anchored expression runs as a regular-expression search and must start with `^` or a literal prefix of at least four characters (after any leading `\b`), which may occur anywhere in the line. It may not use back references, lookaround or inline flags; no repeat may hold another repeat (an optional group included), a repeat that can match more than once may not hold an alternation, at most four repeats may each match more than 16 characters, a path holds at most two open gaps (`.` or a negated class, repeated), whose upper bounds sum to at most 360 characters (an unbounded open gap is refused), and two wide repeats of positive classes that can take the same characters need a mandatory item neither takes between them. Each expression is also timed at load against lines built from its examples and from each repeat's own class to make it backtrack, and refused when one line takes longer than 5 ms over its window (the fastest of three runs). Every pattern runs on every line; a pattern's telemetry classes only rank a match on a class it names above one on another.
- **Matcher** (`evidence.mention_match`). A gate regex anchors each literal at its rarest character, so the engine skips at C speed over positions that anchor nothing; an Aho-Corasick automaton lists every literal, but only around the gate's matches. An anchored expression runs only where its literal prefix occurs (at most four places per line), over a window of 512 characters; one with an end anchor runs only where the line's real end is inside that window. A line where the prefix occurred more often than it is tried, or where the window ended before the line did and the expression could have matched past it (a match that reaches the window's edge included), is counted as not ruled out. Each match gives its offset, and every view shows the text around it.
- **Pool.** A matching record is one mention, under the strongest pattern any of its texts matches (the earliest loaded among equals); the other patterns it matches are kept on it as labelled metadata. Every pattern runs on every line; its telemetry classes only rank a match on a class it names above one on another. Mentions are grouped by (pattern, host, normalized text of the field that pattern matched) in a private SQLite stage. The stage is a yielding store of the hunt's state budget: it has no floor, gives way before any detection store would refuse a key, and when a detection store needs disk the budget reclaims the pool's bytes (the weakest groups' kept records first, then the weakest groups), counted as not kept. The pool is bounded per pattern, per host and per hunt; past a cap a group is not kept, but its lines are still counted, so remainders are exact. At the host and hunt caps a stronger pattern's group takes a weaker one's place; at a pattern's cap a host the pattern has no group on takes a place from the host it has most groups on. Every (pattern, host) that lost lines is stored (`mention_loss`) and paged on the web. Pool order is pattern strength, then the telemetry hint, then rarity (the pattern's distinct hosts, then its matching lines), then first time. At the end of the sweep the pool replaces the hunt's stored pool in one transaction (`mention`, `mention_loss`, `mention_scan`). Each mention's first record is kept on the raw-record path (`agent_raw_record`, origin `mention_sweep`), cleaned, redacted and bounded; these rows never count toward the agent's raw-record cap, and a record the agent's own query returns becomes the agent's, under its cap and with its provenance.
- **Lane.** `mention` is a lane of its own between context and lead, stored outside the findings table. Ranking, triage, expansion, entities, incidents and hypothesis decisions never read it. The report manifest carries the pool's coverage and its top mentions under `mentions`; Markdown, DOCX, the web *Mentions* tab and the agent's dossier and `list_mentions` tool show them labelled as mentions. No alias is issued for a mention, so the agent cannot cite one: it corroborates a mention with typed evidence and cites that. The dossier lists mentions after every finding, so on a large hunt they miss its first page: orient's first message therefore carries the pool's strong and medium groups (at most 15, in pool order, text bounded and flagged) beside the page, and every investigate session's card carries the pool's header, its strongest strength and the count of its groups on each host the hypothesis's findings name, whenever the pool holds anything (weak groups alone included); the investigate playbook pages it once with `list_mentions`. When findings cite the same source record, the shown mention names them (`Repo.mention_citations`, read when the pool is shown, bounded by the page): a typed finding citing a typed event the normalizer made from the record when it offered it (an audit group's process title; the mention keeps those event ids, `linked_events`, found through the candidate-event index), and an AI finding citing the raw record. A typed event made from the record another way is not linked, so a count of 0 is not a statement that no finding rests on it; it stays one mention in its own lane and changes no finding. A lead resting on raw text only comes from the agent reading the raw record itself and judging it; such a lead is labelled a mention, has low confidence and no ATT&CK technique.
- **Coverage.** The pool `scanned every offered record` (never a statement that there are no mentions), or is `partial`, or `not_scanned` (no patterns). It is partial, each with its counts and names, for a partition the sweep could not read in full, records outside the sweep's selection not read (past the budget, by key) or not counted exactly (then the sources the fetch filters leave out are named: Linux text datasets and shapes not retrieved, Windows classes not selected or channels outside the catalog's), a record without scannable text or scanned only in part, a line cut at the bound, a line not ruled out, a cap, a stage write refused or disk reclaimed, a refused or changed pattern file, a scan that failed, or a stop. A scan that raises costs the pool that partition, never its detection. The pool's coverage does not change the detection result.

## Network-to-host join

`detect.net_host_join` (`corr.network_admin_logon`) joins the administration sessions that the sweep's network findings
cite (SMB, RPC, WinRM, RDP, SSH, Telnet and the r-services) to the logon the destination host recorded from that
client, and to the process and share records in that logon session. Host records often carry no address of the host
itself, so the join never maps addresses to hosts. It is keyed on the client endpoint the destination writes into its
own logon record, strongest first: the client address and port (4624/4625, 5140/5145, sshd's `Accepted` line); the
host's own record of the connection (Sysmon 3 or an audit socket record) plus a portless logon of a type the protocol
produces; or a portless logon on the only host with one in the window, when the client held no other session of that
logon class to another address. Records written on the client or by a domain controller (4648, 4768, 4769, 4776) are
never read. The logon must fall within the session's recorded lifetime widened by five minutes (the Windows Kerberos
clock tolerance, which bounds the host clocks whose domain logons are read); for SSH, Telnet and the r-services, which
authenticate when the connection opens, only within five minutes of the opening. A client endpoint the client also used
toward another server in the window, and an address-only pairing for a session only a later stage read, are
unresolved. Anything else is unresolved with its
reason, counted on the rule's coverage, and never a negative; VNC and X11 sessions are named unresolved, since they
leave no typed host logon.

- **State.** Both sides are compact rows on the rule's disk spill (the sweep reads one target before the next), joined
  at finalize. Remote logon sessions and, for each, a count and its earliest process and share records are in keyed
  stores. A process record read before any remote logon naming its session (a target read earlier) is not joined, and
  the item says so.
- **Order.** The rule is finalized after every other rule has published (`after_findings`). It reads the hunt's urgent,
  high and lead findings from the store in full, then the session records they cite, and publishes one item per
  (destination host, client address, protocol).
- **After the packet and baseline stages** (`hunt.net_join_pass`). The sweep keeps the join's rows (sessions, logons,
  host connections, remote logon sessions and their activity, and what each pass judged and published) in
  `<stage directory>/join/<hunt id>.db`, written whole and moved into place, and only while the stage volume has room
  above its reserve. A second pass, before ranking, joins the sessions the packet and baseline stages' findings cite
  (the first-seen administration pair among them) against those rows, reading a cited session the sweep never read
  from the cited record itself. A session is judged once and an item is republished only when its content changed, as
  a revision of the same item, so a resume adds nothing twice. Its summary is the `hunt.join_summary` audit; a resume
  runs the pass until that says finished, and never runs the sweep again to rebuild rows: missing rows leave the later
  stages' sessions unresolved, named, on the rule's window cell. The rows are removed when the pass finishes, when the
  hunt is deleted, and at the next hunt's start for hunts that no longer exist or whose pass finished. Findings of
  expansion reaches and of the AI agent are never joined.
- **Lane.** The item is a lead labelled as an inferred link, with its key and each logon's offset from the session
  start. It is high only when a typed host finding the hunt published at high or urgent cites a process or share record
  in a logon session the join reached by the client endpoint or the host's own connection record (an address-only
  join never raises it), and it never touches the network finding's own lane. Cited host records are kept
  compact and their bodies are fetched by native id when the item is published.

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
decisions. Recognized lines of these programs that carry no event are counted with a named reason. Privilege
brokers (sudo with its optional fields and refusal reasons, su and runuser from util-linux and shadow-utils, pkexec)
are `privilege_use` records; their command and working directory are kept as the caller's text. The shadow-utils
account tools' lines are `account_change` records with the same actions and operations as the tools' audit records,
and a tool that logs one change once per account database has only its `/etc/group` (or final) line typed. Account
and broker records carry the writer's pid (journald's `_PID`, the shipper's `process.pid` or the syslog header's,
each with its own origin) so rules can join them to the process's exec, and name the identifier the line was
logged under and the process journald says wrote it; a claim resting on a line whose writer journald contradicts or
cannot confirm says so. A sudo record sudo split across lines is joined within a batch (same host, account and
writer pid, within seconds); a part left unjoined stays a partial record. The kernel's module taint notices
(out-of-tree, unsigned, non-GPL license) are `kernel_module` load records without a process or file, and are never
taken as evidence that module-load auditing is in place. BIND's zone-transfer denials and started transfers are
`dns_query` requests the server logged. OpenVPN also logs under the `ovpn-<instance>` identifier Debian's
`openvpn@.service` sets. Authentication sessions are distinguished from authentication decisions. Firewall
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
- Once the results the model has already been sent, older than the latest two (a result the model has not been sent yet is never stubbed), reach 32,000 estimated tokens (at most a quarter of a smaller context), or the whole prompt reaches 90,000 tokens (the previous call's reported prompt and output plus an estimate of what was added since; after an edit, an estimate that leaves out each turn's provider state, which repeats its text) and they hold at least 8,000, all of them are replaced at once by stubs: the tool, its arguments, status, counts, negative statement, cursor and next chunk, and every alias the result issued (aliases stay issued, so they stay citable). A stub carries no telemetry text and never changes once written. The model's own turns and the results of the tools that record its work are never compacted.
- Why two and 32,000: on a prompt-cached provider most of an investigation's weighted token spend is cache writes (about 1.25 times the input price), not reads (about 0.1 times). Every new result and reply is written once anyway; a compaction also writes again everything after its first stubbed result, the kept results included. Keeping fewer whole makes each compaction rewrite less; the threshold batches compactions so that stale results are not re-read for long. The prompt ceiling keeps a session below a 100,000-token line, past which some providers bill a whole prompt at a higher rate; its minimum keeps it from rewriting the tail on every call once the model's own turns fill the prompt. The provider's own context editing is not used: each clearing pass rewrites the cached conversation in the same way, and the harness's stubs keep the aliases and handles the model needs to re-read a result.
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
