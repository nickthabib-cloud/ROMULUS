# Operator quick-start

This guide takes you from a fresh Linux host to a finished hunt, a published report and the web UI. It covers only the steps an operator has to take. For what ROMULUS does and how it is configured in depth, see the [README](../README.md) and [`.env.example`](../.env.example).

## 1. Prerequisites

| Need | Notes |
|---|---|
| Linux host | ROMULUS is developed and run on Ubuntu. Use a service account that owns the ROMULUS home. |
| Python 3.12 or later | With `venv`. The deploy script creates the venv with the host's `python3`, so that must be 3.12+ too. |
| TShark | On `PATH`, or set `TSHARK_BIN`. Needed when `ES_INDEX_PATTERNS` includes an Arkime session index: `doctor` then fails without it, and only warns otherwise. |
| Disk | The stage directory (`ROMULUS_STAGE_DIR`, default `$ROMULUS_HOME/stage`) holds staged events and detector state during a hunt. Put it on a volume no other service writes to, never the volume holding Elasticsearch, Arkime or docker data. `doctor` warns under 10 GB free in the home. |
| Elasticsearch 8+ or OpenSearch 2.4+ | Network reach from this host, and an account with **read access to the telemetry indices only**. Never the `elastic` superuser or an OpenSearch `all_access` account; `doctor` fails on those. |
| Arkime viewer | Network reach to its API (directly, or behind a proxy under a path prefix). Its session indices are read through Elasticsearch/OpenSearch, and the packets of selected sessions are fetched from the viewer and decoded with TShark. Without an Arkime session index in `ES_INDEX_PATTERNS`, hunts skip the packet stage and need neither Arkime nor TShark. |
| Model endpoint (optional) | The AI investigating agent needs one: the team's own model server, or a remote endpoint the operator has approved for the hunt's data (see [Model providers](../README.md#model-providers) and section 8). Without one, hunts run deterministically and the agent is reported as not configured. |

## 2. Install

Both install routes below use the same layout, which `scripts/web-restart.sh` expects: `$ROMULUS_HOME/app` (the code), `$ROMULUS_HOME/venv` and `$ROMULUS_HOME/.env`.

**From a checkout on the host:**

```bash
export ROMULUS_HOME=<romulus-home>               # an absolute path the service account owns
mkdir -p "$ROMULUS_HOME" && chmod 700 "$ROMULUS_HOME"
git clone <repository-url> "$ROMULUS_HOME/app"
python3.12 -m venv "$ROMULUS_HOME/venv"
"$ROMULUS_HOME/venv/bin/pip" install -e "$ROMULUS_HOME/app"
# AGENT_PROVIDER=anthropic also needs its optional SDK:
# "$ROMULUS_HOME/venv/bin/pip" install -e "$ROMULUS_HOME/app[anthropic]"
```

**From a Windows workstation with the deploy script** (needs Git, OpenSSH and SSH access to the host):

```powershell
powershell -File scripts/deploy.ps1 -Target <ssh-host> -RemoteHome <romulus-home>
# -Extras anthropic installs the optional SDK; -SkipInstall copies the code without reinstalling dependencies
```

The script copies the working tree to `<romulus-home>/app` (keeping the previous copy as `app.old`), creates `db`, `logs`, `reports` and `cache`, runs `chmod 700` on the home, creates the venv if missing and installs the package. It records the shipped commit in `app/DEPLOYED_COMMIT`. It never creates or changes `.env`.

### The `.env` file

```bash
cp "$ROMULUS_HOME/app/.env.example" "$ROMULUS_HOME/.env" && chmod 600 "$ROMULUS_HOME/.env"
```

Then edit it. `doctor` fails if the file is readable by anyone but its owner.

| Variable | Required | Notes |
|---|---|---|
| `ROMULUS_HOME` | yes | Set it to the same `<romulus-home>`. The template's value is an example; a command run without `ROMULUS_HOME` exported takes the home from this line. |
| `ROMULUS_SECRET_KEY` | for the web UI | A random value of 32+ characters without spaces, e.g. `python3 -c "import secrets;print(secrets.token_urlsafe(32))"`. It signs web sessions; `doctor` fails without a fit one and `romulus web` refuses to start. |
| `ES_URL`, `ES_FLAVOR` | yes | `ES_FLAVOR` is `elasticsearch` or `opensearch` and must match the cluster. |
| `ES_USERNAME` + `ES_PASSWORD`, or `ES_API_KEY` | yes | The read-only account. An API key, when set, is used instead of the username. |
| `ES_CA_CERT`, `ES_VERIFY_TLS` | for TLS | The CA that signed the cluster's certificate. Keep verification on. |
| `ES_INDEX_PATTERNS` | yes | Comma-separated index or data-stream patterns, including the Arkime session indices. Without them there is nothing to hunt. |
| `ES_READ_ONLY_ROLES` | OpenSearch | The names of your read-only roles, so `doctor` can show the account is read-only. |
| `ARKIME_URL`, `ARKIME_USERNAME`, `ARKIME_PASSWORD` | with an Arkime index | Plus `ARKIME_BASE_PATH` and `ARKIME_AUTH` (`digest` or `basic`) behind a proxy. Use an `https` URL with `basic`. |
| `TSHARK_BIN` | as needed | The TShark binary, when it is not `tshark` on `PATH`. |
| `PCAP_ALLOWED_DIRS` | no | `doctor` checks that each listed directory exists. Hunts fetch packets from Arkime, not from these directories. |
| `ROMULUS_INTERNAL_NETWORKS`, `ROMULUS_EXTERNAL_NETWORKS` | strongly advised | The site's address space and carve-outs (CIDRs). Unset, the RFC 1918 ranges are assumed, rules that depend on direction report partial coverage and `doctor` warns. They can be set on the web UI's Site setup page instead, not in both places. |
| `MISSION_TIMEZONE` | no | Times given without an offset are read in this zone (default `UTC`). |
| `ROMULUS_STAGE_DIR` | advised | See Disk above. |
| `AGENT_*` | for the AI agent | See section 5, section 8 and [Model providers](../README.md#model-providers). |

**Secrets go only in this file:** `ROMULUS_SECRET_KEY`, `ES_PASSWORD`, `ES_API_KEY`, `ARKIME_PASSWORD` and `AGENT_API_KEY`. ROMULUS redacts their values from logs, prompts and reports; never put them in a command line, a script or a ticket. `doctor` warns about secrets that are short or easy to guess.

The commands below assume this shell helper:

```bash
romulus() { "$ROMULUS_HOME/venv/bin/romulus" --env-file "$ROMULUS_HOME/.env" "$@"; }
```

`--env-file` and `--json` are global options: they go **before** the command (`romulus --json findings <hunt-id>` with the helper).

## 3. Web exposure

`romulus web` serves on `ROMULUS_WEB_BIND` (default `127.0.0.1:8443`). On a loopback address it may serve plain HTTP, reachable only from the host itself. On any other address it refuses to start without TLS. Pick one of the following.

**Built-in TLS.** Give it a certificate and key and bind to the network:

```bash
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=romulus" -keyout "$ROMULUS_HOME/key.pem" -out "$ROMULUS_HOME/cert.pem" && chmod 600 "$ROMULUS_HOME/key.pem"
# .env: ROMULUS_WEB_BIND=0.0.0.0:8443  ROMULUS_WEB_TLS_CERT=<romulus-home>/cert.pem  ROMULUS_WEB_TLS_KEY=<romulus-home>/key.pem
```

Set both files or neither. `doctor` fails if either file cannot be read or the key is readable by every local user. A self-signed certificate suits a small team; use one your site's CA issued when there is one.

**Behind a TLS reverse proxy.** Keep `ROMULUS_WEB_BIND` on loopback and set:

- `ROMULUS_WEB_TRUSTED_PROXIES`: the proxy's IP address (`127.0.0.1` for a proxy on the same host). Single addresses, comma-separated; networks and `*` are refused. Only these proxies' `X-Forwarded-For`/`X-Forwarded-Proto` headers are trusted, so the login throttle and the audit log see the real client address.
- `ROMULUS_COOKIE_SECURE=1`, so the session cookie is only ever sent over HTTPS.

**`ROMULUS_WEB_ALLOW_PLAINTEXT=1`** accepts plain HTTP on a network address. It exists for an isolated lab only: passwords and session cookies then cross the network unencrypted, which anyone on the path can read and replay. Do not use it on a mission network. `doctor` warns about it, and `romulus web` prints a warning when it starts.

## 4. First run

### `doctor`

```bash
romulus doctor                      # add --check-timeout SECONDS to give every check the same deadline
```

Each line is `[OK  ]`, `[WARN]` or `[FAIL]`. **FAIL** means a hunt started now would fail, stall, or run on an unsafe setup; fix it first. `doctor` exits 1 when any check fails. **WARN** means something is not verified or is weaker than it should be; read it, but a hunt can run. `doctor` only reads: it never writes to your telemetry or migrates the database.

On a fresh install, expect these warnings: `db.integrity` (no database yet; it is created on first use), `site.collection` (no `site/collection.yaml`; optional) and, until the site's networks are set, `site.internal_networks`.

`packets.scope` says whether a hunt would run the packet stage, that is whether `ES_INDEX_PATTERNS` includes an Arkime session index. When it does, or when that cannot be told because the cluster could not be read, `arkime.reachable` and `tshark` fail as usual. When it does not, they only warn that the packet stage will be skipped, so a host without Arkime passes `doctor`.

The checks you are most likely to act on:

| Check | Status | What to do |
|---|---|---|
| `es.reachable` | FAIL | Check `ES_URL`, network reach, credentials and the TLS settings (`ES_CA_CERT`, `ES_VERIFY_TLS`). |
| `os.flavor_version` | FAIL | Set `ES_FLAVOR` to what the cluster is; ROMULUS needs Elasticsearch 8+ or OpenSearch 2.4+. |
| `es.account` | FAIL | The account is a superuser (`elastic`, `superuser` or `all_access`). Use a read-only account. |
| `es.index_patterns` | FAIL | `ES_INDEX_PATTERNS` is empty, so a hunt refuses to start. Set it. |
| `es.index[<pattern>]` | FAIL | The pattern resolves to no index. Fix `ES_INDEX_PATTERNS`. |
| `es.least_privilege`, `os.read_only` | FAIL / WARN | FAIL: the account can write. Remove write privileges. WARN: read-only could not be shown (on OpenSearch, set `ES_READ_ONLY_ROLES`). |
| `arkime.reachable` | FAIL / WARN | Check `ARKIME_URL`, `ARKIME_BASE_PATH`, `ARKIME_AUTH` and the credentials. HTTP 401 usually means the wrong scheme or password. WARN: no Arkime session index is configured, so it is not needed. |
| `tshark` | FAIL / WARN | Install TShark or set `TSHARK_BIN`. WARN: as for `arkime.reachable`. |
| `paths.pcap[<dir>]` | FAIL | A `PCAP_ALLOWED_DIRS` entry does not exist. |
| `paths.env_mode` | FAIL | `chmod 600` the `.env`. |
| `paths.home_mode` | WARN | `chmod 700` the home and the stage directory. |
| `state.budget` | FAIL / WARN | See Troubleshooting: stage disk. |
| `stage.volume`, `disk.free` | WARN | Move `ROMULUS_STAGE_DIR` to its own volume; free space. |
| `web.tls` | FAIL / WARN | See section 3. |
| `web.secret_key` | FAIL | Set `ROMULUS_SECRET_KEY` (section 2). |
| `site.internal_networks` | WARN | Set the site's networks (section 2) and check the hosts it names as outside. |
| `agent.*`, `triage.*` | FAIL / WARN | See Troubleshooting: agent endpoint. `agent.provider` OK with "agent not configured" is fine for a hunt without the agent. |
| `secrets.length`, `secrets.strength` | WARN | Replace the named secret with a long random value. |
| `db.integrity`, `db.space` | WARN | See Troubleshooting: database. |

### Web UI accounts

```bash
romulus user add <name> --role lead        # asks for the password twice (12+ characters)
romulus user add <name> --role analyst     # --role defaults to analyst
```

Create at least one lead. To manage accounts later:

| Command | Effect |
|---|---|
| `romulus user disable <name>` / `romulus user enable <name>` | Block or restore the account's logins. |
| `romulus user role <name> --role lead\|analyst` | Change its role. |
| `romulus user passwd <name>` | Set a new password (asked interactively). |
| `romulus user logout <name>` | End its web sessions. |

Every one of these ends the account's open web sessions at once, and each change is written to the audit log.

## 5. A hunt

```bash
romulus hunt start --start 2026-01-01T10:00:00Z --end 2026-01-01T17:30:00Z
```

- The window is `[start, end)`. A time without an offset is read in `MISSION_TIMEZONE`.
- The hunt runs in the foreground and prints urgent and high findings as they are found, then a summary line. Run it under `tmux`, `screen` or `nohup` for long windows, or start it from the web UI (whose hunts log to `$ROMULUS_HOME/logs/hunt-<time>.log`).
- **AI agent:** when it is configured and `AGENT_DEFAULT=on` (the template's value), the agent runs after the deterministic stages. `--no-agent` skips it for this hunt and `--agent` asks for it when `AGENT_DEFAULT=off`. The choice is fixed when the hunt is created. If the agent is requested but blocked, the hunt says so and runs without it; deterministic results never depend on it. `--effort quick|standard|deep` sets the agent's budget for this hunt (see the [Commands](../README.md#commands) table for the per-limit flags).
- `--style directed --hypothesis "<text>"` focuses the hunt on one hypothesis.

| Command | Use |
|---|---|
| `romulus hunt status [<hunt-id>]` | Every hunt (or one): state, headline result, lane counts, packet, expansion and agent progress. |
| `romulus hunt stop <hunt-id> [--agent-only]` | Ask a running hunt (or only its agent) to stop at its next safe point. `--force` ends a worker that has not stopped within `ROMULUS_HUNT_STOP_GRACE_SECONDS`. |
| `romulus hunt resume <hunt-id>` | Continue a stopped, interrupted or partial hunt. It reruns a sweep that stopped part-way, then the stages that did not run. It keeps the hunt's recorded agent choice, so `--agent` and `--no-agent` are refused here. `--agent-only` continues only an agent run that ended partial. |
| `romulus findings <hunt-id> [--lane urgent --lane high]` | List ranked findings; lanes are `urgent`, `high`, `lead` and `context`. |
| `romulus report <hunt-id>` | Publish a new, immutable report revision. |

### Outputs

`report` writes to `$ROMULUS_HOME/reports/<hunt-id>/` and prints each path:

| File | Contents |
|---|---|
| `<revision>.json` | The report manifest: the single source every other output is rendered from. |
| `<revision>.md` | The technical report: findings, incidents, attack path, recommendations, coverage, coverage gaps and data not assessed. |
| `<revision>.docx` | The executive report, including recommendations and coverage limitations. |
| `<revision>-iocs.csv`, `<revision>-iocs-stix.json` | Indicator export as CSV and a STIX 2.1 bundle. |
| `fleet-hosts-<digest>.jsonl`, `zeek-visibility-<digest>.jsonl` | Appendices, when a finding or the coverage section needs them. |

Recommendations are a section of the Markdown and DOCX reports, not a separate file. If the DOCX or the indicator export cannot be written, a note (`<revision>.docx-error.txt` or `<revision>.iocs-error.txt`) says why, and the other files are still written. `report` exits 1 in that case, and also when the revision is not finalizable (it has broken citations). The web UI's Report tab publishes and downloads the same files.

### Reading a result

- **Headline result:** `reportable_findings`, `leads_only`, or `no_qualifying_observation_in_assessed_scope`. The last means that nothing qualified in what was searched. It never means the network is clean.
- **Execution state:** `planned` (created, not yet started), `running`, `completed_within_scope`, `partial` or `failed`. A partial hunt (part of a source could not be read, a cap or time limit was reached, the stage disk hit its reserve, or someone stopped it) says what did not run and is never shown as complete. `hunt resume` reruns a sweep that was stopped part-way and the stages after the sweep that did not finish. It does not search again partitions that a finished sweep left partial: start a new hunt over that window for those. A `failed` hunt (a source preflight or sweep error) whose sweep did not finish cannot be resumed; fix the cause and start a new hunt. A `planned` hunt cannot be resumed either: delete it and start again.
- **Coverage:** each rule reports `searched in full`, `searched in part` or `not assessable by design` (rules that can find something but cannot show it is absent). Coverage gaps lists every partition a rule did not fully search, and why. Data not assessed lists data in scope that no rule read. A baseline that could not be judged is `unresolved`, as is a link or a time range that could not be resolved. Caps, timeouts, missing fields and partial responses always appear in one of these forms, never as "no match". (`unresolved` is also a disposition an analyst can set on a finding.)

### Other commands

| Command | Use |
|---|---|
| `romulus agent reassess <hunt-id> [--max-calls N] [--max-tokens N]` | Write a fresh AI assessment for a stored hunt (optionally with extra calls or tokens) and publish a new report revision. |
| `romulus triage <hunt-id> [--force] [--agent-model <id>]` | Run the AI triage pass on a finished hunt: a labelled, promote-only order over the surfaced findings. The deterministic report order stays authoritative; run `report` afterwards to publish it. |
| `romulus triage <hunt-id> --no-run --export <file> [--allow-stale]` | Export the stored triage order as JSON without calling the model. |
| `romulus indicators import <file> --name <name> --source <source> [--lane high\|lead\|context] [--reason <text>] [--expires <ISO>]` | Import a local CSV or STIX/MISP JSON indicator file as a new list version (default lane `lead`, expiry 90 days). A `high` lane asks for a lead account's password and needs `--reason`. `--list-id` adds a version to an existing list. |
| `romulus indicators export <list-id> [--version N] [--format yaml\|csv] [--out <file>]` | Export a complete list version. |
| `romulus sigma import <dir> --upstream <url> --commit <id>` | Import a local directory of Sigma rules; they arrive as `draft` or `reference-only`. |
| `romulus sigma list [--status <status>]` / `romulus sigma show <rule-id>` | List or show the imported rules. |
| `romulus sigma activate <rule-id> --positive <file> --benign <file> [--lane lead\|high] [--reason <text>]` / `romulus sigma retire <rule-id>` | A lead account (its password is asked) activates a rule only when its positive fixture matches and its benign fixture does not, or retires it. |

## 6. Web UI

```bash
bash "$ROMULUS_HOME/app/scripts/web-restart.sh"     # start or restart; prints the pid or the log tail on failure
```

The script runs `romulus web` in the background, records its pid in `$ROMULUS_HOME/web.pid` and logs to `$ROMULUS_HOME/logs/web.log`. It needs the layout from section 2. It does not start the UI after a reboot.

To keep the UI running across reboots, run it under systemd instead of the script (use one or the other, never both: they would compete for the port). A minimal unit, for example `/etc/systemd/system/romulus-web.service`:

```ini
[Unit]
Description=ROMULUS web UI
After=network-online.target
Wants=network-online.target

[Service]
User=<service-account>
Environment=ROMULUS_HOME=<romulus-home>
ExecStart=<romulus-home>/venv/bin/romulus --env-file <romulus-home>/.env web
Restart=on-failure
# keep files the UI writes (reports, hunt logs) private to the service account
UMask=0077
# hunts started from the UI run as child processes: stopping or restarting the UI must not end them
KillMode=process

[Install]
WantedBy=multi-user.target
```

Then `sudo systemctl daemon-reload && sudo systemctl enable --now romulus-web`. Its output goes to the journal (`journalctl -u romulus-web`); a refusal to start (section 7) is the last line there.

Open `https://<romulus-host>:8443/login` (or the proxy's address) and log in with an account from section 4. Sessions last at most 8 hours. Five failed logins in five minutes lock that account for a while; other accounts are not affected.

| Role | Can |
|---|---|
| `analyst` | View hunts, findings, incidents, the timeline, mentions and reports; start hunts; set finding dispositions; stop or extend the agent budget of hunts they started, within the site ceiling (`AGENT_BUDGET_CEILING_MULTIPLIER`). |
| `lead` | Everything an analyst can, plus: stop or extend any hunt, go above the budget ceiling, force-stop a worker, delete hunts, run an AI reassessment and edit the Site setup page. |

## 7. Troubleshooting

**A source is unreachable.** `doctor` shows `es.reachable` or `arkime.reachable` as FAIL with the error text. Check, in order: network reach from this host to the URL; the URL's scheme and port; `ES_CA_CERT` or `ES_VERIFY_TLS` for a certificate error; the credentials; for Arkime behind a proxy, `ARKIME_BASE_PATH` and `ARKIME_AUTH`. A source that fails during a hunt is named in the result as a coverage gap or a partial reason. Fix the source, then start a new hunt over the affected window: `hunt resume` does not read again what a finished sweep could not. A host with no Arkime viewer needs no Arkime session index in `ES_INDEX_PATTERNS`: hunts then skip the packet stage and say so, and `doctor` only warns about Arkime and TShark.

**The web UI will not start.** `web-restart.sh` prints "web failed to start" and the end of `logs/web.log`.

- `romulus web: refusing to serve plain HTTP on <address>`: the bind is not loopback and no TLS is set. Use one of the options in section 3.
- `set both ROMULUS_WEB_TLS_CERT and ROMULUS_WEB_TLS_KEY`: only one is set.
- `ROMULUS_WEB_TRUSTED_PROXIES entry ... is not a single IP address`: list each proxy's address, with no networks and no `*`.
- `romulus web: ROMULUS_SECRET_KEY ...` ("is empty" or "must be a random value of 32+ characters without spaces"): set it (section 2). `doctor` reports the same as `web.secret_key`.
- A TLS error from the server: run `doctor` and read `web.tls`; a key file must be readable by the service account and by nobody else.

**`doctor` warns about the database.**

- `db.integrity`, "schema at ..., this build expects ...": the store is from an older version. Any command that opens it for work migrates it, e.g. `romulus hunt status`. Restart the web UI afterwards.
- "could not be opened read-only by this user": run `doctor` as the service account that owns the home.
- "integrity check did not finish": a large store; give it longer with `--check-timeout`.
- `db.space` says space is reclaimable: run `romulus db compact` while no hunt is running.

**The stage disk is short.** `state.budget` FAIL means the stage volume's free space is already below its reserve, so rules that keep state would evaluate nothing. Free space, or point `ROMULUS_STAGE_DIR` at a larger volume that no other service uses. The reserve is the larger of `ROMULUS_STATE_DISK_RESERVE_GB` and 15% of the volume. A hunt's detector state may use `ROMULUS_STATE_DISK_GB`, or by default the smaller of half the free space and 10% of the volume. `state.budget` WARN means that total is under 1 GiB. A hunt that reaches the reserve becomes `partial` and names what it did not evaluate; it does not crash. After freeing space, start a new hunt over the window its coverage gaps name.

**The agent endpoint fails.** Run `romulus doctor` and read the `agent.*` lines.

- "agent not configured: AGENT_BASE_URL is empty" (or `AGENT_MODEL`, `AGENT_API_KEY`): set them. With `AGENT_PROVIDER=anthropic`, "needs its optional SDK" means install the `anthropic` extra (section 2).
- "agent blocked: ... is a remote endpoint": the endpoint is not loopback, private (RFC 1918 or IPv6 unique-local) or listed in `MODEL_LOCAL_HOSTS`. If the server is your own, list its host or network in `MODEL_LOCAL_HOSTS`. For a remote endpoint you have approved for the hunt's data, set `ROMULUS_MODEL_EGRESS=lab-public-data` (section 8).
- "agent blocked: ... is set but ... not set above 0": a cost budget needs every price setting it names.
- `agent.reachable` or `agent.model` FAIL: check the URL, the key and the model id. `romulus doctor --agent-model <id>` tests another model id without changing `.env`.
- `agent.timeout` WARN: raise `AGENT_TIMEOUT_SECONDS` as the warning says.

A hunt whose agent was blocked or failed keeps all its deterministic results. After a fix, `hunt resume <hunt-id> --agent-only` continues an agent run that ended partial (the provider became unavailable, or it was interrupted, stopped, or given more budget). For a hunt with no agent run to continue, start a new hunt over the same window.

## 8. Remote model endpoints

An endpoint is local when its host is loopback, private (RFC 1918 or IPv6 unique-local) or listed in `MODEL_LOCAL_HOSTS`. Telemetry excerpts may go to any other endpoint only when the operator has approved that endpoint for the hunt's data and opts in explicitly with `ROMULUS_MODEL_EGRESS=lab-public-data` in `.env` (the value keeps its name for existing installs). A remote endpoint must use `https`. `doctor` names it in `agent.egress`, and every hunt and report that used it carries a banner naming the host and model. Without the opt-in, the agent is blocked and the hunt runs without it.
