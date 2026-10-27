# ROMULUS

> **Early proof of concept, under active daily development.** I'm actively brainstorming changes and improvements. I just threw it together and I'm not married to anything - I appreciate any reccomendations!

**ROMULUS is a defensive threat-hunting tool.** It searches host and network telemetry for signs of compromise and reports what it finds as ranked, cited findings, incidents and an attack-path timeline.

It is built for cyber defense teams (Cyber Protection Teams, SOC and incident-response analysts) who are dropped onto a network with logs in Elasticsearch or OpenSearch, sessions in Arkime and packet captures on disk.

ROMULUS works **with or without an AI model**. Initial finding comes from deterministic, typed detection rules. The AI investigating agent works on top of those results, correlating and furthering investigations with custom queries and follow ups. operating without the model just presents analysts with rules/signature based query results for analysis.

---

## How it works (In progress)

1. **Sweeps** the hunt window across your sources with a catalog of typed detection rules: web shells, reverse shells, credential-file reads, downloads piped to a shell, firewall tampering, privilege-escalation tooling, port scans, beaconing, suspicious IDS alert stacks, indicator matches and much more. The goal is to find any malicious activity the telemetry can show, on any mission network. The detection catalog is being built from systematic research:
  - MITRE ATT&CK Enterprise and ICS techniques;
  - Public detection corpora (Sigma, CAR, Atomic Red Team, LOLBAS/GTFOBins, ET Open and others);
  - Any telemetry family a hunt may meet: Windows, AD, Linux, macOS, identity and cloud logs, network devices, Zeek, Suricata, PCAP and ICS protocols.
3. **Reads packets** for the sessions that matter: it fetches them from Arkime by session ID and decodes them with TShark (for example, a file whose content does not match its claimed type).
4. **Expands** from the strongest findings along typed links (the same process tree, the same login session, the same network flow) and judges the linked activity in that context: discovery commands, privilege probing, credential access, data staging and lateral movement that would be too weak on their own.
5. **Assembles incidents**: findings joined by observed links, with a cited, time-ordered narrative. Inferred links are shown, but always labelled as hypotheses.
6. **Ai Agent Investigation**: Ai agent reviews initial round of sweeps and develops hypothesis. It then follows leads, creats custom queries, and develops its own attack path narrative based on further findings.
7. **Reports**: an immutable report revision (JSON and Markdown) and a browser UI with findings, incidents and an attack-path timeline.



## Current Supported data

| Source | Today | Planned |
|---|---|---|
| Linux auditd | ✓ | |
| Linux journal | ✓ | |
| Apache access and error logs | ✓ | other web servers |
| Suricata alerts and flows | ✓ | |
| Arkime sessions (via its Elasticsearch indices) | ✓ | |
| PCAP via Arkime and TShark | ✓ | more protocols |
| Windows / Active Directory, Zeek, cloud and identity logs, ICS protocols | | ✓ |

Sources are read through Elasticsearch or OpenSearch with **read-only** credentials. ROMULUS never writes to your telemetry.

## Findings and lanes

| Lane | Meaning |
|---|---|
| `urgent` | Strong evidence of attacker activity; look now |
| `high` | Strong indicator that needs confirmation |
| `lead` | Worth an analyst's look; uncertain or grouped activity (batches say so) |

Nothing that might be attacker activity is dropped: noise is handled by grouping similar records into one finding, never by hiding them.

## Requirements

- Currently A Linux host for ROMULUS (it is developed on Ubuntu)
- Python 3.12+
- Elasticsearch or OpenSearch holding the telemetry, and an account with read access to the indices only
- Arkime (sessions and PCAP), TShark, PCAP files in an allow-listed directory
- A model server (see [AI investigating agent](#ai-investigating-agent-in-progress))

## Quick start

```bash
git clone https://github.com/nickthabib-cloud/ROMULUS.git && cd ROMULUS
python3.12 -m venv venv
venv/bin/pip install -e .

export ROMULUS_HOME=~/romulus && mkdir -p "$ROMULUS_HOME"
cp .env.example "$ROMULUS_HOME/.env" && chmod 600 "$ROMULUS_HOME/.env"
# edit .env: ES_URL, ES_USERNAME/ES_PASSWORD (read-only), ES_INDEX_PATTERNS, ROMULUS_SECRET_KEY, optional Arkime and PCAP settings

venv/bin/romulus --env-file "$ROMULUS_HOME/.env" doctor
venv/bin/romulus --env-file "$ROMULUS_HOME/.env" hunt start --start 2026-01-01T10:00:00Z --end 2026-01-01T17:30:00Z
venv/bin/romulus --env-file "$ROMULUS_HOME/.env" report <hunt-id>
```

`doctor` checks connectivity, that the account is read-only, the configured indices, TShark, the PCAP paths and storage, and tells you what to fix.

To use the browser UI:

```bash
venv/bin/romulus --env-file "$ROMULUS_HOME/.env" user add alice --role lead
venv/bin/romulus --env-file "$ROMULUS_HOME/.env" web      # serves on ROMULUS_WEB_BIND (default 127.0.0.1:8443)
```

## Commands

| Command | What it does |
|---|---|
| `doctor` | Checks sources, privileges, tools, model endpoint (if any) and storage |
| `hunt start --start <ISO> --end <ISO>` | Runs a hunt: sweep, packet stage, expansion and incidents. Deterministic by default |
| `hunt start ... --style directed --hypothesis "<text>"` | A hunt focused on one hypothesis |
| `hunt resume <id>` / `hunt status [id]` | Continue an interrupted hunt / show progress |
| `findings <id> [--lane urgent --lane high]` | List ranked findings |
| `report <id>` | Publish a new immutable report revision (JSON and Markdown) |
| `user add <name> --role lead\|analyst` | Create a web UI account (interactive) |
| `web` | Serve the browser UI |
| `db compact` | Return the space freed by deleted hunts to the disk |

Add `--json` for machine-readable output.

## Configuration

All settings live in `$ROMULUS_HOME/.env` (template: [`.env.example`](.env.example)). Keep it `chmod 600` and never commit it. The main groups:

- **ROMULUS:** `ROMULUS_HOME`, `ROMULUS_WEB_BIND`, `ROMULUS_SECRET_KEY`, `MISSION_TIMEZONE`
- **Elasticsearch/OpenSearch:** `ES_URL`, `ES_FLAVOR`, credentials or `ES_API_KEY`, TLS options, `ES_INDEX_PATTERNS`
- **Arkime and packets:** `ARKIME_URL`, credentials, `PCAP_ALLOWED_DIRS`, `TSHARK_BIN`
- **Model (optional):** see below

**Site facts** live in `$ROMULUS_HOME/site/collection.yaml`. A lead edits them on the web UI's **Site setup** page:

- what each group of Windows hosts collects (Sysmon event ids, audit policy subcategories, command lines in 4688, PowerShell script blocks, event log channels);
- the domain controllers and directory-sync accounts;
- the site's internal networks. These can be set here or with `ROMULUS_INTERNAL_NETWORKS`/`ROMULUS_EXTERNAL_NETWORKS` in `.env`, but not both.

Windows logs cannot show whether a kind of event was being recorded at all. Results therefore name the collection that was not attested, so analysts can see where the hunt was blind. ROMULUS reports what it finds; it never claims that nothing is there. Every change is validated and audited, and hunts record the file's digest. A stopped hunt cannot resume after the file changes; start a new hunt over its window instead.

## AI investigating agent (In progress)

After the deterministic hunt, an AI agent will read everything ROMULUS found, form hypotheses about what the attacker did, follow leads through typed, read-only pivots, and open the report with a cited **AI assessment**, labelled as AI-generated and unconfirmed. It can add findings (marked as agent findings), but it can never hide, close or demote anything the deterministic layer found.

- Teams connect it to **their own model server**, so telemetry stays on their network.
- A hosted model is allowed only for testing on public data, behind an explicit install-time switch, with a banner on every hunt and report that used it.
- Usage is bounded by per-hunt budgets (calls, tokens, time, optional cost). If a budget runs out, the deterministic results are unaffected.

Full design: [`docs/architecture/ai-investigating-agent.md`](docs/architecture/ai-investigating-agent.md).

- **Strong indicators are reported on their own, immediately.** Correlation and attack paths come second.
- **Nothing reportable is lost** to UI limits, model context or rendering. One report manifest feeds every output.
- **Read-only and on-site.** ROMULUS never writes to your telemetry and sends nothing off the host it runs on (except the optional, labelled test-model exception above). Secrets never appear in logs, prompts or reports.


## Architecture

```
sources (ES/OpenSearch, Arkime, PCAP) ─► sweep ─► packet stage ─► expansion ─► incidents ─► report ─► JSON | Markdown | web UI
                                                                                  └─► AI agent (planned)
```

Python 3.12 modular monolith (`src/romulus/`), SQLite (WAL) as the single state store with Alembic migrations, FastAPI + Jinja web UI with local logins, roles, CSRF protection and a strict CSP. Details: [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md) and the generated [`MODULE_MAP.md`](docs/architecture/MODULE_MAP.md).

## Security and intended use

- ROMULUS is for **authorized, defensive** threat hunting on networks you are permitted to analyze.
- It is not hardened for exposure: the web UI has no built-in TLS yet. Bind it to localhost or put it behind a TLS reverse proxy on a trusted network.


## Development

```bash
venv/bin/pip install pytest respx ruff
venv/bin/python -m pytest -q -p no:warnings
venv/bin/ruff check src tests
python scripts/archmap.py --check     # architecture dependency rules
```

Repository layout:

| Path | Contents |
|---|---|
| `src/romulus/` | `config`, `store`, `sources`, `evidence`, `detect`, `decide`, `hunt`, `agent`, `report`, `web`, `cli` |
| `tests/` | Unit, adversarial and regression tests |
| `content/` | Indicator lists and vendored MITRE ATT&CK data |
| `scripts/` | Deploy helper, web restart, architecture map, live smoke test |
| `docs/architecture/` | Architecture, module map, AI agent design |

## Roadmap

- **Next:** the AI investigating agent; deeper network and packet analysis; host rules that can prove negatives from kernel file records.
- **Then:** detection breadth (Windows/AD, Zeek, Sigma import, ATT&CK coverage matrix), testing on unseen datasets, the executive DOCX report and hardening.


