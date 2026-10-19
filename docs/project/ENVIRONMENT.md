# Lab environment facts

Verified facts only, each dated. Mark anything inferred as _inferred_. Secrets never go here. The integration-tester and lead keep this file current.

## Topology (verified 2026-10-18)

| Component | Where | Notes |
|---|---|---|
| Windows host | VMnet1 `192.168.36.1` | RTX 4060 Laptop 8 GiB (driver 560.94), i7-13700HX, 31.7 GiB RAM (~9 GiB free with VM up), ~640 GB free on C:. No git or uv installed yet. Python 3.13. |
| Ollama | Windows host, `OLLAMA_HOST=192.168.36.1:11434` | v0.40.3. Models: `qwen3:8b` (Q4_K_M, 5.2 GB). No `OLLAMA_FLASH_ATTENTION` / `OLLAMA_KV_CACHE_TYPE` / `OLLAMA_CONTEXT_LENGTH` set. Reachable from the VM. |
| Ubuntu VM | `192.168.36.128`, SSH alias `romulus-vm` (key `~/.ssh/romulus_vm_ed25519`) | Ubuntu 24.04.5, kernel 6.8.0-146, 6 vCPU, 9.4 GiB RAM (~4.6 GiB available), 4 GiB swap, 146 GB root with 81 GB free. Python 3.12.3. `user` is in the `sudo` group (password required) but not in `docker`. |
| Elasticsearch | VM `127.0.0.1:9200`, plain HTTP | 9.5.5, cluster `docker-cluster`, but runs natively from `/usr/share/elasticsearch` (~3.2 GB RSS). `romulus_agent`: cluster `monitor`; read on the lab indices only (no write/delete/manage). |
| Kibana | VM `192.168.36.128:5601` | ~1.2 GB RSS |
| Arkime | VM `:8005`, systemd `arkimeviewer` | 6.3.1 (`capture --version`). Digest auth. 24,630 sessions. |
| TShark | VM `/usr/bin/tshark` | 4.2.2 |

## Data (verified 2026-10-18)

- `romulus-host-logs-sl700-e-a`: 1,775,149 docs, 962 MB. Datasets: systemd.journal 918,647; linux.audit 770,658; apache.access 46,977; host.ghosts 22,473; zoneminder 14,768; apache.error 1,626. `@timestamp` 2024-06-05 → 2024-11-18T17:17:30Z.
- `romulus-network-logs-sl700-e-a`: 147,685 docs, 82 MB. Suricata EVE http 46,612; fileinfo 35,661; flow 24,565; netflow 22,663; dns 16,487; alert 1,491; tls 137; ssh 69. 2024-06-21 → 2024-11-18T17:13:20Z. Hosts: inetfw, corpdns.
- Both indices use the same 48-field ECS-like mapping produced by v1's importer (`/home/user/ainception-agent/agent/import_*.py`). `process.command_line`, `process.executable`, and `url.original` are `wildcard` type; `event.original` and `message` are `text`. `event.module` is unpopulated.
- PCAPs, `/opt/arkime/ainception-input/sl700_variant_e_a/`:
  - `corpdns_suricata_1731925346.pcap` (1.04 GB)
  - `corpdns_suricata_1731948751.pcap` (1.04 GB)
  - `inetfw_suricata_1731924645.pcap` (184 MB)
  - `inetfw_suricata_1731927869.pcap` (626 MB)
- Protocol hierarchy: HTTP, TLS, SSH (bulk of corpdns bytes), DNS, Kafka, mDNS, NTP, RTSP/RTP (CCTV). **No ICS protocols.**
- Source archives: `~/datasets/SL700_variant_e_a_stage/SL700_variant_e_a.zip` (3.65 GB); `~/ainception-agent/data/archive/SL700_variant_a_b.zip` plus extracted `staging/run_a_b` (**contaminated**: used by v1).
- Ground truth: `/home/user/romulus-eval/sl700_e_a/` (eval-custodian only). Mode 700/600 throughout (tightened 2026-10-19). The hunt runtime runs as the same Unix user, so only config and code keep it out (owner remedy pending: separate account).
- Dataset quirks (verified 2026-10-19 by the eval-custodian):
  - `inetfw_suricata_1731927869.pcap` is truncated at its end (capinfos: last packet cut short). TShark negatives over it must be `partial`.
  - Some long-lived TCP sessions are in Arkime and the PCAPs but have no Suricata flow record in the network index.
  - The `systemd.journal` dataset carries journald copies of auditd records (~180k in the attack span), so the same audit event can appear twice under different datasets.
  - AttackMate timestamps are naive UTC (offset 0 h, aligned on 7 anchors to ≤ ~1 s).
  - The dataset's `alerts/` folder (AMiner, Telosian) embeds ground-truth labels: it must never become a ROMULUS source.

## Malcolm (not deployed)

Not present. Proposed: a separate VM (≈16 GiB RAM, 4–6 vCPU, ≥200 GB), installed from CISA's official GitHub releases with verification, started only for M4 integration. Awaiting owner decision.

## Owner-only actions (need sudo or host changes)

- Install on Windows: Git (`winget install --id Git.Git -e`) and uv (`winget install --id astral-sh.uv -e`).
- Later: VM resize to 12 GiB / 8 vCPU (before M3); Ollama env `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0` if the bakeoff shows a benefit.
