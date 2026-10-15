# ROMULUS

ROMULUS is a single-agent defensive threat-hunting application. It accepts a broad or focused mission, inspects configured telemetry schemas, registers every evidence search in one persisted scheduler, interprets and correlates evidence, then keeps proposing new searches until the evidence, candidate dispositions, source coverage, or hunt budget says to stop. A focused mission may create operator-directed hypotheses immediately. A broad mission first runs deterministic discovery and creates hypotheses only after a telemetry-backed candidate exists. It records provenance, builds cited attack paths, and writes Word and plain-text reports. The offline demonstration uses synthetic events.

## What is implemented

- One iterative LangGraph analyst loop with persistent checkpoints: mission direction or deterministic discovery → unified search scheduler → shared candidates → evidence-backed hypotheses → bounded pivots → candidate disposition and coverage closure → report. Catalog, indicator, directed, candidate, model, and coverage searches all use the same task identity, ordering, execution, and outcome contract.
- Local Ollama reasoning is gated by evidence basis. Focused missions may use the operator's direction for initial deterministic hypotheses and searches, but ROMULUS does not spend a model call before telemetry collection. Undirected missions form no hypothesis until deterministic telemetry produces a candidate. The model may assess those hypotheses and propose validated searches, but it cannot create additional hypotheses. A model-selected finding is admitted only when it names an already supported hypothesis, uses its ATT&CK mapping, and cites at least two records that pass deterministic entity checks; the published observation and confidence basis are then generated from those checked records rather than model prose.
- Guarded native query generation. The model can propose Elasticsearch Query DSL, Arkime expressions, and TShark display filters when native syntax better expresses an analytic idea. ROMULUS checks each proposal against a bounded read-only grammar and the discovered source fields, enforces the mission time range, and rejects malformed candidates. Every plan also carries structured selectors so deterministic compilation can continue the hunt when a native proposal is rejected. The model cannot invoke arbitrary tools or run shell commands.
- Up to 24 hypotheses, at least 3 reasoning rounds, 10 rounds maximum, 160 tool calls, and 10 minutes by default. Discovery reserves an opportunity for each healthy configured host/network family before repeated work from one family. Investigation tasks use deterministic evidence-value tiers; the model may propose grounded searches but cannot set its scheduler tier. The hunt stops on candidate-aware coverage closure or a hard limit, rather than merely because a queue became empty.
- Deterministic behavioral analytics run over the complete unique evidence set persisted in SQLite, independently of the smaller checkpoint/model context. Candidate citations and records sharing exact structured entities are promoted back into that bounded context, up to 200 records per analysis pass, before correlation and reasoning. Coverage reports the persisted, checkpoint, and promoted counts separately.
- Aggregate analytics cover authentication failure-to-success, privileged logon followed by execution, authentication fan-out, remote service followed by execution, network fan-out, periodic edges, rare external destinations, DNS entropy/NXDOMAIN bursts, DNS query fan-out, HTTP path fan-out, known scanner user agents, scan followed by a reverse connection, protocol-port mismatch, outbound byte outliers, rare process/destination pairs, and staging followed by transfer. The model receives these compact cited observations together with promoted representative evidence.
- Official Elasticsearch Python client, allowlisted index patterns, mapping inspection, constrained Query DSL, least-privilege metadata discovery, exact hit counts, and bounded PIT/search-after pagination when supported. Capped searches allocate their retained rows across deterministic time strata using explicit mission bounds or the matching result extent; initial host collection uses tactic-diverse surveys instead of one cap-filling OR query.
- Arkime authenticated session API adapter. Capped ordered result sets are sampled through stable rank windows spanning the available result set, with duplicate suppression and explicit disclosure when Arkime's maximum offset prevents full rank coverage. The reported version-specific URL/API behavior and authentication must be verified on the target installation; this project does not guess credentials.
- TShark offline PCAP wrapper with an explicit configured path allowlist, a shared planner/adapter field contract, display-filter character restrictions, no shell, and a timeout. It scans the complete approved capture or explicit time slice, counts all matches, and retains a deterministic time-stratified reservoir. Missing or malformed packet timestamps use a disclosed whole-stream deterministic reservoir.
- A pinned, offline Enterprise ATT&CK v19.2 catalog generated from MITRE's official STIX bundle: 697 active techniques/sub-techniques, 697 Detection Strategy links, and 1,745 platform Analytic links. ROMULUS selects a bounded mission-relevant and tactic-diverse planning view, then enriches the 39 most operationally useful techniques with local search selectors and benign alternatives. Deterministic candidate hypotheses may remain unmapped when the observed behavior does not justify a technique, so ATT&CK guides the hunt without forcing a label.
- Typed cross-domain entity/time leads with direction, scored reasons, and explicit NAT, DHCP, clock-skew, and attribution caveats.
- A deterministic investigation graph connects observed entities and activities to evidence. Finding paths use only evidence IDs cited by that finding; temporal or shared-entity relationships are labeled inferred, never causation, and disconnected evidence remains separate with explicit gaps.
- Persistent scheduler tasks, queues, attempts, exact outcomes, bounded resumable checkpoints, durable unique evidence, append-only finding events, and per-call audit JSONL while a hunt is active. Exact execution fingerprints merge duplicate work while preserving every candidate, follow-up, hypothesis, and origin that owns the result. Interrupted read-only tasks are disclosed and requeued at most once. Graph context is capped per source and baseline/pivot phase.
- Automatic reports with separate audiences: the styled `.docx` is a concise customer deliverable covering the assessment, findings, supported attack path, scope, ATT&CK context, limitations, and recommended actions; the `.txt` preserves technical investigation detail, cited path provenance, bounded scheduler ownership/outcomes, and unresolved source-fairness gaps without dumping query bodies.
- Default `compact` retention runs only after a completed hunt's matching Word and text reports can both be reopened and identified as belonging to that hunt. It keeps the reports, conclusions, findings, cited evidence, supported path, compact coverage, aggregate sampling/scheduler counts and gaps, and source-error summary, while removing full task/query/outcome history, uncited raw evidence, hunt-scoped JSONL working records, and checkpoints. Partial hunts remain resumable until explicitly finalized. `full` retention preserves all working data.
- CLI commands: `doctor`, `test`, `hunt`, `resume`, `inspect`, `compact`, `finalize`, and synthetic `demo`.

The agent does not need the user to name every TTP or write a query. A focused lateral-movement mission can expand into SMB, RDP, SSH, WinRM, DCOM/WMI, authentication patterns, service/task execution, and nearby post-access behavior because the operator supplied that direction. A broad mission does not guess an attacker path: it starts with repeatable artifact and telemetry discovery, promotes observed behavior into candidates, and only then forms a cited hypothesis. Each round can pivot to a different source, entity, time cluster, or competing explanation. Search results are capped and the report records where coverage stopped. No finding is never a claim that the environment is clean. ROMULUS does not perform active scans, endpoint changes, or other disruptive actions.

Representative retrieval reduces the earlier earliest-result bias but does not turn a capped search into complete coverage. Elasticsearch uses time strata, Arkime uses ordered rank windows, and TShark uses deterministic reservoirs over the complete matching stream. Every capped outcome remains partial and cannot close a hypothesis. The technical report records the strategy, covered/requested strata, retained count, and fallback reason. Sparse strata, unknown totals, malformed timestamps, source timeouts, or Arkime's offset ceiling can still leave gaps; use narrower windows or higher authorized limits when complete review is required.

Arkime integration follows the [official v3–v6 API reference](https://arkime.com/apiv3), which documents HTTP Digest authentication, `/api/sessions`, `date=-1`, and the `start` offset. Arkime protocol expressions use `protocols` (plural). A date-only mission end is inclusive through 23:59:59.999 UTC. ROMULUS requests stable first-packet ordering and overlap-aware time bounding, probes the matched total, then distributes up to `ARKIME_MAX_RESULTS` (default 20,000) across stable rank windows. It suppresses duplicate session rows and records matched totals, caps, covered windows, and offset-limit fallbacks. Broad missions include TCP, UDP, and ICMP sessions; model-generated searches add targeted coverage, including protocols on nonstandard ports. Generic network follow-ups use Arkime as the first-line session source and fall back to approved PCAPs when Arkime is unavailable; explicit TShark investigations still inspect each selected capture.

The reported Arkime `pcapDir=/dev/shm/arkime-raw` expiry error is a separate storage issue from `/api/appinfo` authentication. Arkime documents `pcapDir` as storage for saved raw PCAP files and notes that session metadata may remain after raw PCAP files are removed. If this Viewer is expected to retain or serve captured packets across restarts, configure an existing persistent directory with the required ownership/write access and free space. Arkime advises keeping `pcapDir` off the same filesystem as its Elasticsearch/OpenSearch data directory. If ROMULUS only reads existing sessions and scans the explicitly configured AInception PCAP files with TShark, that path is not required for ROMULUS's direct PCAP reads. See [Arkime PCAP storage settings](https://arkime.com/settings).

## Behavioral hunt catalog

The editable starting behavior list, trusted IOC file, scoring policy, and extension instructions are documented in [docs/behavior-analytics.md](docs/behavior-analytics.md).

The [intelligence document index](docs/research/README.md) explains the authoritative sources, generated files, research notes, and the meaning of each runtime state. The generated [priority inventory](docs/research/indicator-priority-inventory.md) lists all 902 curated behaviors by name, priority, and current state without exposing query JSON. Of those behaviors, 636 have reviewed executable semantics and 266 remain reference only with a named gap. Live reports distinguish loaded rules from rules that were executable, actually evaluated, matched, partial because of source limits, or still warming a baseline.

## Project components

`romulus/agent/` contains the local model interface. `romulus/investigation/` owns the single-agent graph, unified scheduler, safe selector validation, source-query compilers, bounded evidence context, and budgets. `romulus/tools/` contains deterministic read-only source adapters. `romulus/intelligence/` holds normalization, the pinned official ATT&CK catalog, curated query-enrichment layer, behavioral analytics, and deterministic correlation. `romulus/store.py` persists the complete unique evidence set, hunt state, and events. `romulus/reporting/` creates reports. The model assesses existing evidence-backed hypotheses and proposes searches; code validates citations, entities, ATT&CK ownership, query parameters, source constraints, and priority before acting or publishing a finding.

Query languages stay source-specific: Elasticsearch takes JSON Query DSL; Arkime uses its own session expression syntax; TShark uses a display filter (`-Y`). BPF capture filters are not used because the application reads offline captures. Kibana KQL is not sent to Elasticsearch. These syntaxes are not interchangeable.

## Windows development / Ubuntu deployment

The VM, Elasticsearch, Arkime, and Ollama were exercised during prior live investigations; their reachability and data can change. `doctor` checks current configuration and connectivity on Ubuntu before a hunt. The code still treats `.env` paths, credentials, and indexes as deployment configuration, not universal constants.

### Transfer and prepare Ubuntu

From PowerShell in the directory containing the archive, copy it to the VM:

```powershell
scp .\ROMULUS.zip user@192.168.36.128:/home/user/ROMULUS.zip
```

On Ubuntu, extract into the dedicated ROMULUS directory and create a project-local Python environment (Ubuntu 24.04 / Python 3.12):

```bash
cd /home/user
unzip -o /home/user/ROMULUS.zip -d /home/user/ROMULUS
cd /home/user/ROMULUS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
nano .env
```

The ZIP excludes secrets and runtime state. It does not install system packages. If Ubuntu reports that `venv` is unavailable, stop and arrange for the standard Ubuntu `python3-venv` package through the system administrator; ROMULUS does not silently install OS packages.

### Configure `.env`

Review the defaults and set values confirmed on the VM:

- `ROMULUS_HOME`, `DATA_DIR`, `LOGS_DIR`, `REPORTS_DIR`: keep them under `/home/user/ROMULUS` unless you deliberately choose another local path.
- `MISSION_TIMEZONE`: timezone used for mission timestamps that omit `Z` or an explicit UTC offset. Set it to the timezone used by the analyst-facing Kibana/Arkime display, such as `America/New_York`. ROMULUS converts those bounds to UTC consistently for Elasticsearch, Arkime, and TShark. Explicit offsets always take precedence.
- `OLLAMA_URL`, `OLLAMA_MODEL`: reported defaults are `http://192.168.36.1:11434` and `qwen3:8b`.
- `ES_URL`, `ES_USERNAME`, `ES_PASSWORD`, `ES_INDEX_PATTERNS`, `ES_LOOKBACK_HOURS`, `HISTORICAL_SEARCH`: use a read-only service account. With `HISTORICAL_SEARCH=true` (default), ROMULUS searches configured indices across retained history with behavior-focused queries and a bounded result cap; explicit ISO dates in the mission take precedence. Set it to `false` to use the `ES_LOOKBACK_HOURS` rolling window. Index discovery and mapping use APIs covered by `view_index_metadata`; document searches require `read`. No cluster `monitor` or index `monitor` privilege is required. Never put the password in a report, shell command, or shared archive.
- `ARKIME_URL`, `ARKIME_USERNAME`, `ARKIME_PASSWORD`, `ARKIME_API_PATH`, `ARKIME_DATE_HOURS`: the adapter uses `/api/sessions` with HTTP Digest authentication. Historical search is `date=-1` by default when `HISTORICAL_SEARCH=true`; explicit mission dates take precedence. `ARKIME_DATE_HOURS` applies when historical search is disabled. `/api/appinfo` is not used. The S2S secret is not an agent credential.
- `PCAP_ALLOWED_DIRS`, `PCAP_FILES`: list only approved existing PCAP directories/files. ROMULUS rejects paths outside the configured directories.
- `TSHARK_BIN`: use the executable name or an absolute path available to the service user.
- `MAX_TOOL_CALLS`, `MIN_REASONING_ROUNDS`, `MAX_DEPTH`, `MAX_RUNTIME_SECONDS`, `MAX_RESULTS`, `ARKIME_MAX_RESULTS`, `TIME_SAMPLING_STRATA`, `CONTEXT_EVIDENCE_PER_SOURCE`, `TOOL_TIMEOUT_SECONDS`, `MAX_RETRIES`: adjust investigation bounds to suit the VM. Defaults are 160 tool calls, at least 3 and at most 10 analyst reasoning rounds, 10 minutes, up to 10,000 Elasticsearch results per query, 500 returned packets per TShark query, up to 20,000 Arkime sessions per query, eight representative sampling strata, and 1,000 graph-context records per source/phase bucket. Sampling strata are code-controlled (2–24) rather than model-controlled. Existing `.env` files are preserved during archive extraction, so change these values there if you want different bounds.
- `RETENTION_POLICY`: `compact` (default) safely removes nonessential hunt working data after successful final reporting; `full` preserves all evidence, checkpoints, and hunt-scoped JSONL records.

Protect `.env` (`chmod 600 .env`) and do not copy it into the ZIP. The default ES index patterns are exactly the two reported names. `doctor` prints availability and error classes/statuses, never password values.

### Validate and operate

```bash
cd /home/user/ROMULUS
source .venv/bin/activate
python main.py doctor
python main.py test
python main.py demo
python main.py hunt --objective "Conduct a broad threat hunt for malicious activity across available host logs and network traffic. Develop and pursue multiple hypotheses, correlate evidence, and keep exploring distinct leads until no useful read-only searches remain or a configured limit is reached."
python main.py hunt --objective "Investigate possible lateral movement and consider alternate remote execution paths and related authentication, service, and scheduled-task evidence."
python main.py hunt --retention full --objective "Investigate a case that requires complete working-data retention."
```

Offline demo needs no live services and creates a synthetic investigation, JSONL events, SQLite state, and `.docx`/`.txt` report. To repeat a hunt with only the sample sources, use `python main.py hunt --offline --objective "Hunt for SMB lateral movement"`.

For a live hunt, run `doctor` first and review every unconfigured/failed source. `doctor` now returns failure when a required configured service, model, directory, PCAP, iterative-reasoning preparation, or TShark field contract is not ready. Missions can be broad or focused; state the time/asset boundary when one is required. Reports, findings, and state are saved under configured project-local paths. A returned `HUNT-...` ID can be used with:

```bash
python main.py resume --id HUNT-XXXXXXXXXX
python main.py inspect --id HUNT-XXXXXXXXXX
python main.py finalize --id HUNT-XXXXXXXXXX
python main.py compact --id HUNT-XXXXXXXXXX
```

Runtime files: `data/romulus.sqlite3` stores investigations and evidence; `data/checkpoints.sqlite3` stores the newest resumable graph checkpoint per namespace; `logs/findings.jsonl` is the working finding event stream; `logs/tool_audit.jsonl` stores non-secret per-call metadata; `reports/` contains generated Word/text reports. Under the default compact policy, completed hunts retain only cited evidence, compact investigation state, and aggregate scheduler coverage; full scheduler/query/attempt history, checkpoints, and hunt-scoped JSONL working records are removed after report verification. Partial hunts retain their working data for `resume`; `finalize --id` deliberately closes and applies the configured retention policy. Use `compact --id` to retry or apply compact retention to an already completed legacy/full hunt. A retention cleanup failure is reported as a warning and a distinct exit status while leaving the reports and conclusion intact. Use `inspect --id HUNT-...` to see the retained outcome and retention status. Back retained files up according to local operational policy.

Releases before 0.4.1 stored every graph snapshot in `romulus.sqlite3`. With no hunt running, rebuild that legacy file and remove superseded checkpoint bulk with:

```bash
python -m scripts.compact_store
```

The compactor verifies operational table counts and SQLite integrity before replacing the database. Add `--keep-backup` when local policy requires retaining the pre-compaction file.

## Safety and evidence interpretation

Only use ROMULUS against systems/data you are authorized to investigate. Elasticsearch and Arkime should use read-only accounts. Packet and log content is untrusted; embedded instructions are ignored. The demo finding is labeled suspected and explicitly notes that entity/time correlation cannot prove identity or malicious intent. An isolated SYN is not treated as a completed connection. No finding is not proof that the environment is secure. PCAP searches are limited to configured files, allowlisted fields, a retained-match cap, and an execution timeout. Active scanning and endpoint changes are outside this version.

## Local development and verification

`python main.py test` runs the repository's unit/synthetic suite; `python main.py demo` is the offline demonstration. During an active or resumable hunt, the agent stores each model reasoning round, accepted/rejected search plan, scheduler task and owner, exact execution fingerprint/outcome, source result count, and evidence-linked model assessment. Prior releases passed deployment diagnostics and controlled live hunts on the development VM; current unified-scheduler proof and remaining VM/holdout gates are recorded in [VALIDATION.md](VALIDATION.md). Validation remains an engineering exercise rather than operational authorization.

Development history, verification evidence, and known limitations are maintained in [CHANGELOG.md](CHANGELOG.md). Security assumptions and reporting guidance are in [SECURITY.md](SECURITY.md).

To update the offline ATT&CK catalog deliberately, run `python scripts/update_attack_catalog.py --release <version>` and review the recorded source URL, SHA-256, counts, and diff before committing. The current generated catalog is pinned to the official Enterprise v19.2 JSON release; hunts do not download ATT&CK data.
