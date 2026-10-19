# Network sources and host↔network correlation

**Status:** Owner-directed 2026-10-19 ("correlate host logs and network telemetry to find indicators and help the investigator follow leads"). Built on branch `m2/network-correlation` in parallel with investigator v2, and merged after it.

## Why

M2 scoring showed both c2_channel opportunities missed at the *retrieved* stage. The host evidence (auditd `connect` records) was never normalized, Arkime and PCAP were never read, and nothing joined a host process to the network traffic it caused. Suricata alerts and flows were evaluated in isolation, as their own stream.

## Lab facts (verified 2026-10-19, read-only probes)

- **Suricata EVE:** every record (alert, flow, netflow, http…) carries `community_id`. It is already normalized as `network.community_id`.
- **Arkime:** 688 SPI fields, including `communityId`, JA3, HASSH, certificates, HTTP host/URI, bytes and packets. The sessions API answers (11,435 sessions involve one lab server), and Arkime can return the packets of a single session.
- **auditd:**
  - The lab's audit rules record `connect` only: 14,995 calls in the hunt window, no accept or bind. They carry the key `T1043_Commonly_Used_Port`.
  - SOCKADDR records hold the raw sockaddr in hex: inet, inet6, local (Unix), netlink and unspec.
  - Outbound connections are therefore visible host-side, and inbound ones are not.
- **`host.ip` is empty for every host.** Host↔IP identity must come from an operator asset map, or be inferred from joins and labelled as inferred.

## Slices

### Slice 1: host sockets and the Suricata join (this branch, first)

1. **`net_socket` event family** from auditd SYSCALL + SOCKADDR (+ PROCTITLE) groups.
   - **Syscalls:** connect, accept, accept4 and bind, by (arch, number). x86_64 and aarch64 are supported; other arches are skipped with a counted reason.
   - **Fields:** `socket.syscall` and `socket.family`; the remote endpoint (`destination.ip`/`destination.port` for connect, `source.*` for accept); and the same `process.*` fields as `process_exec` (pid, ppid, executable, comm, uid/euid/auid, user names, tty), plus `audit.key`.
   - **Outcome:**
     - `success=yes` → success;
     - `exit=-115` (EINPROGRESS: a non-blocking connect that was started) → unknown, with a caveat;
     - any other failure → failure.
   - **Non-IP families** (local, netlink, unspec) are skipped and counted. A socket SYSCALL without SOCKADDR becomes an event without a destination, carrying a caveat; rules then count it as missing a required field, never as no-match.
2. **`host.interpreter_external_connection`** (direct). A shell, interpreter or network-relay binary (by kernel-recorded `process.executable`), or any process of a web-service account, called `connect()` to a non-private address. High when a web-service account is involved, otherwise lead.
   - **Positive-only:** the audit rule set's scope (which syscalls, families and ports it records) is not visible in telemetry, so absence of a record proves nothing.
3. **`corr.process_network_link`** (aggregate across the host and network targets). Each IP `connect` is joined to network records with the same remote address and port whose start lies within −3 s…+5 s of the call. The join is a correlation, never an observation:
   - the claim states each observed fact with its source (auditd record; Suricata flow/alert);
   - it labels the link as inferred (address/port/time);
   - it states when more than one internal source address could match.
   - The lane is never higher than the strongest observed component.
   - Published when the joined network side carries an IDS alert, or when the process side is itself suspicious (as in rule 2), so an alert is attributed to a process and a suspicious process gets its network evidence.
4. **Inferred host addresses.** For a host, the internal source address of uniquely joined flows (count of agreeing joins out of the total) is recorded in the claim as the "address observed for this host". It is never written as an asset fact. An operator asset map (`ASSET_MAP` file, optional) overrides it and is cited as configuration.

### Slice 2: Arkime source adapter

- Read-only `GET /api/sessions` with `bounding=first` (sessions partitioned by first packet), time windows in epoch seconds, a fixed field list, paging, and completeness from `recordsFiltered` vs. returned. Any page cap, error or unknown count makes the result partial.
- Expressions are compiled by the adapter from typed predicates only (IP, port, protocol equality). Free text, model text and user text are never accepted.
- **`net_session` family:**
  - `network.community_id`, the 5-tuple, bytes and packets per direction, first/last packet and duration;
  - JA3/JA3S, HASSH/HASSH-server, TLS SNI and certificate subject/issuer, HTTP host/URI/user agent, DNS host;
  - the Arkime session ID and node, as the raw locator.
- Joins: Suricata↔Arkime on `community_id` (exact, same flow); host↔Arkime as in slice 1.
- **First network rules on Arkime fields:**
  - long-duration or high-volume sessions to rare external peers;
  - periodic sessions (beaconing) by peer;
  - rare JA3/HASSH per environment;
  - self-signed or short-validity certificates on external peers;
  - cleartext interactive-shell heuristics are left to slice 3.

### Slice 3: packet evidence through Arkime

TShark runs on the packets of specific sessions fetched from Arkime (never a blind scan of every capture). It is bounded by bytes and time, with display filters built from typed fields only. It is used by rules that need content (cleartext commands, downloaded file magic), and as an investigator tool that opens a session's content. The PCAP allowlist checks and the truncated-capture caveat (`inetfw_suricata_1731927869.pcap`) still apply.

## Investigator tools (after investigator v2 lands)

Menu options for:
- `process_connections(host, pid)`: the process's sockets and joined flows;
- `flow_detail(community_id)`: Suricata records, the Arkime session and any host socket for one flow;
- `peer_activity(ip)`: every host process and session touching a peer.

These go to Codex through the v2 option generator.

## Invariants kept

- **Typed fields only.** Joins use typed address, port, time and community_id values, never text.
- **Inferred links are labelled hypotheses** and never create observed facts.
- **Positive-only rules never write a complete negative.** Arkime unknown counts, caps and truncated PCAPs make results partial.
- **Read-only toward every source.**
