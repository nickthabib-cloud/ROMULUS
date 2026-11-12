# Network protocol contracts

Typed field origins name the source record and native field. Missing values remain missing. A recognized malformed application subrecord rejects its enclosing EVE record atomically and is counted as a normalization error. A protocol that is not implemented is counted as not normalized.

`detect.network_producers.protocol_record(event, family)` checks the exact family and a known producer identity. It does not prove that a particular record contains every field a rule needs. Rules must retain their field, outcome, identity and coverage checks. The helper accepts Zeek and Suricata protocol contracts; it excludes Arkime's unordered session sets from transaction rules.

`rule_reads(event, producers)` is the gate each network rule applies. The RPC administration, coercion and replication rules, the WinRM rule, the RDP rules and the Netlogon, NTLM and RPC enumeration rates read Zeek and Suricata records, since each needs only facts both sensors type alike. An RPC call is identified by endpoint and operation names or by interface UUID and opnum; Suricata records the interface beside the opnum for calls over SMB named pipes, and a standalone DCERPC request record carries only the opnum, so its call is not classified and these rules do not judge it. HTTP and SMB records are in their flow's direction. Suricata writes each RDP message in its packet's direction, so the RDP rules judge only its client's `initial_request` (`rdp.message`), once per connection. An NTLM outcome is typed from the session setup's own status (success, or a listed logon failure) and is otherwise unset, which the rates count as an attempt, as for Zeek. The other network rules read Zeek only: the Kerberos rates (Suricata's request, reply and error records are not typed apart, so a rate would count one exchange more than once), the requested-ticket-lifetime rule (Suricata does not record the requested till), the VNC rule (Suricata RFB records are not normalized) and the SMB admin-share executable rule (Suricata gives no cross-record file identity and direction). A rate that counts raw references keeps its count per sensor, so two sensors on one link do not double it; a rate that counts distinct members shares them across sensors.

## Producer and field matrix

Common available network fields are `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport` and `network.community_id`, when carried by the record. Suricata also preserves `suricata.flow_id`. These are sensor observations, not endpoint execution records.

The following table describes application fields in addition to that common tuple. Every listed field is conditional on the source providing it; a family is not a promise of complete visibility. Zeek's full native and shipper field tables are in `src/romulus/evidence/zeek_catalog.py`.

| Family | Zeek producer | Suricata producer | Arkime producer |
|---|---|---|---|
| `rpc_tx` | `rpc.endpoint`, `rpc.operation`, catalog-derived `rpc.interface_uuid`, `rpc.opnum`, `rpc.op_class` | `dcerpc`, including embedded SMB RPC: `rpc.interface_uuid`, `rpc.opnum`, `rpc.op_class` | No transaction contract |
| `smb_tx` | `smb.command`, `smb.action`, `smb.path`, `smb.share`, `smb.name`, `smb.prev_name`, version/status and file identity fields by log | `smb`: command, status, version, share/path/name/previous name, explicit rename/create request; SMB1 DELETE or explicit SMB2 delete-on-close request, file size/FUID when present | Lists on `net_session`, never `smb_tx` |
| `ntlm_tx` | `ntlm.username`, `ntlm.domain`, `ntlm.hostname`, explicit `ntlm.success`, derived account/name fields | Separate SMB authentication child: username/domain/hostname, `source.hostname`, `user.name`, `user.domain`, `auth.target_account`; `ntlm.success` and outcome only from the same SESSION_SETUP transaction's explicit logon status | Independent username/domain/workstation lists on `net_session` |
| `kerberos_tx` | request type, client/client name, service, ticket cipher and numeric etype, explicit error/outcome and request lifetime fields | `krb5`: `kerberos.request_type`, `kerberos.client`, `kerberos.client_name`, `kerberos.service`, ticket `kerberos.cipher`/`auth.encryption_type`; port-derived `kerberos.client_ip`/`kerberos.kdc_ip`; error message/code, KDC `auth.status` and `kerberos.error_source` only when attributable | Independent principal/service/realm lists on `net_session`; no ticket outcome, etype, lifetime or rate |
| `remote_session` | RDP and VNC protocol and negotiation metadata | RDP protocol, `rdp.message` subtype, cookie, client build/name/channels, desktop dimensions, keyboard layout and client product ID when emitted | No transaction contract |
| `ldap_tx` | operation(s), object(s), argument(s), scope(s), base object(s), attributes, filter, result(s), bind type/version/message ID and observed result count by log | LDAP request/response operation, bind/search fields, scope/base object/attributes, serialized presence filter, explicit result(s); no inferred result count | Bind authentication type and bind-name lists on `net_session` |
| `app_tx` (SMTP) | `app.protocol`, `smtp.helo`, `smtp.mail_from`, `smtp.rcpt_to`, and message metadata | SMTP fields above; email from/to/cc/subject/message ID/user agent when emitted | No SMTP contract |
| `app_tx` (FTP) | protocol, command, argument, reply/code and data-channel fields | `ftp`/`ftp_data`: protocol/command/argument, single reply/code, passive flag and dynamic response port; multiple replies remain unpaired | No FTP transaction contract |
| `app_tx` (SNMP) | `snmp.version`, observed session counters and credential presence | SNMP version and credential presence; no session counters inferred from one PDU | No SNMP contract |
| `app_tx` (TFTP) | No TFTP log in the current Zeek catalog | Generic `app.protocol`, `app.command`, `app.arg`; no Zeek TFTP parity claim | No TFTP contract |
| `address_assignment` | DHCP address, name, MAC, lease and message-type fields | DHCP assigned/client/requested IP, client MAC, hostname, lease and message types | No DHCP contract |
| `net_alert`, `net_flow`, `dns_query`, `http_tx`, `file_transfer`, `tls_session`, `ssh_session` | Existing catalog contracts | Existing EVE alert/flow/netflow/DNS/HTTP/fileinfo/TLS/SSH contracts | Corresponding independent values on `net_session` only |
| `x509_certificate`, `asset_observed`, `sensor_health`, `ics_tx` | Existing catalog contracts | Not admitted by this producer helper | No transaction contract |
| `net_session` | Not produced | Not produced | One session with existing flow/DNS/HTTP/TLS/SSH fields plus the independent sets below; excluded by the transaction helper |

Suricata has producer identity `suricata-eve@2`; Arkime has `arkime@1`. Zeek retains its own producer epoch. Hunt manifests record all producer versions. A saved hunt using an earlier producer identity must be restarted; it cannot mix staged old IDs with newly fetched IDs.

### Suricata interpretation limits

A request/response transaction is one event. An SMB authentication or RPC subrecord gets its own typed family and identity with the enclosing raw reference. Candidate RPC interfaces are not multiplied into calls; multiple unpaired interface candidates leave classification unresolved.

SMB uses flow orientation in [Suricata's SMB logger](https://github.com/OISF/suricata/blob/suricata-8.0.0/src/output-json-smb.c#L68). Its [transaction serializer](https://github.com/OISF/suricata/blob/suricata-8.0.0/rust/src/smb/log.rs#L131) supplies the same SESSION_SETUP record's status and NTLM child. `STATUS_SUCCESS` means success; the explicit logon/account failure statuses in [MS-ERREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) mean failure. More-processing, unrelated commands, other statuses and missing status remain unknown. An SMB2 CREATE or SET_INFO with `access: delete on close` supplies `FILE_DELETE` as a requested operation, not proof of completed deletion. The disposition information-class name alone does not establish deletion.

RDP and Kerberos use packet direction ([KRB5 registration](https://github.com/OISF/suricata/blob/suricata-8.0.0/src/output.c#L1176), [RDP registration](https://github.com/OISF/suricata/blob/suricata-8.0.0/src/output.c#L1231), [tuple construction](https://github.com/OISF/suricata/blob/suricata-8.0.0/src/output-json.c#L492)). Their source/destination tuple is preserved as written, so a server response can have the server as source. RDP clients send `initial_request` and `connect_request`; server-side records include `initial_response`, `connect_response` and `tls_handshake` ([parser](https://github.com/OISF/suricata/blob/suricata-8.0.0/rust/src/rdp/rdp.rs#L211)). All five values become `rdp.message`. Kerberos client/KDC fields use the unique port-88 end for TCP or UDP. Neither or both ends on port 88 leaves these roles unset with a caveat. Non-standard KDC ports are not inferred.

Kerberos `ticket_encryption` on an AS/TGS reply is the issued ticket's encryption type. EVE `encryption` describes a different encrypted part and is not substituted for it; an unknown value adds a caveat without discarding valid ticket facts. Unknown ticket-cipher names remain normalization errors. Names map to numeric etypes through the shared IANA/RFC table; [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961), [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) and [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) describe the algorithms and identifiers. KDC error attribution requires the failed AS/TGS request indication. Missing ticket cipher or error attribution cannot support the corresponding credential rule.

Suricata's `cname` is the principal without an appended realm ([serializer](https://github.com/OISF/suricata/blob/suricata-8.0.0/rust/src/krb/log.rs#L42), [principal formatter](https://github.com/rusticata/kerberos-parser/blob/kerberos-parser-0.8.0/src/krb5.rs#L37)); it becomes `kerberos.client_name` unchanged. Zeek's `kerberos.client` includes its final `/REALM`, which the Zeek adapter already separates into `kerberos.client_name` and `kerberos.client_realm`. A realm is not invented from Suricata's separately emitted service realm.

The Suricata 8 LDAP serializer emits only presence filters. Other LDAP filter forms that it does not serialize stay unknown; no filter or entry count is reconstructed from absent data. RDP client product ID comes from the serializer's client `id` field.

`anomaly`, `quic`, `http2`, `sip`, `mqtt`, `ike`, `pgsql`, `nfs` and `rfb` remain counted as not normalized: their current EVE layouts have no implemented direct correspondence to the required typed contracts. No unsupported record becomes a clean negative.

Format and field semantics follow the [Suricata 8 EVE reference](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) and its [protocol serializers](https://github.com/OISF/suricata/tree/suricata-8.0.0/rust/src).

### Arkime session sets

| Native Arkime field | Typed field on the single `net_session` | Limit |
|---|---|---|
| `smb.share` | `smb.path`, derived share/server lists | No pairing with filenames or users |
| Stored `smb.filename`, search alias `smb.fn` | `smb.name` | No rename/action or transaction count |
| `smb.user`, `smb.domain`, `smb.host` | `ntlm.username`, `ntlm.domain`, `ntlm.hostname` | Host is the NTLM workstation, not the share server |
| `krb5.cname`, `krb5.sname`, `krb5.realm` | `kerberos.client_name`, `kerberos.service`, `kerberos.realms` | Unassociated sets; realm is not assigned to a particular principal |
| `ldap.authtype`, `ldap.bindname` | `ldap.bind_type`, `ldap.objects` | No LDAP search transcript |
| `http.host` on a TLS-only session | `tls.client.server_name` | Shared HTTP host/SNI storage is ambiguous on mixed HTTP/TLS sessions |
| Configured `http.request-referer`, `http.request-origin` | `http.request.referrer`, `http.request.origin` | Independent lists with URI credentials removed |
| Configured Content-Length headers | Not typed as observed body sizes | A declaration does not prove captured body bytes |
| Unordered header names/values | Not zipped into a header map | Persisted ordering/pairing is absent |

The mappings follow Arkime's official [SMB](https://github.com/arkime/arkime/blob/main/capture/parsers/smb.c), [Kerberos](https://github.com/arkime/arkime/blob/main/capture/parsers/krb5.c), [LDAP](https://github.com/arkime/arkime/blob/main/capture/parsers/ldap.c), [TLS](https://github.com/arkime/arkime/blob/main/capture/parsers/tls.c) and [HTTP](https://github.com/arkime/arkime/blob/main/capture/parsers/http.c) field registrations. HTTP SNI/Host attribution and declared-size limits deliberately prevent invented transaction evidence.

Known credential values are masked in both typed evidence and retained raw records. Raw-reference digests cover the stored masked form. Presence/unknown fields retain the observation without the credential value.

## SMB impact observations

`network.smb_impact` folds by client, server and share within a closed five-minute window:

- At least 100 distinct extension-changing destination names with at least 80% sharing one new extension: high lane, critical severity, T1486 context.
- At least 200 distinct renamed/deleted names: lead lane, high severity.
- Exact whole names or bounded anchored forms from `content/network/ransom_notes.json` opened or created in at least 10 directories: lead lane, high severity. Repeated opens in one directory count once. Generic readmes are excluded; case folding preserves Unicode lookalike differences. Names alone do not prove file contents, and incident-response copies remain possible.

Native Suricata 8 rename records do not themselves carry the share path: the serializer emits it on other SMB operation types. This rule does not join tree/session IDs across records. A rename without independently supplied share context is unresolved for this rule; the enriched Suricata fixture proves the typed integration only. Zeek SMB file records already supply the share path.

Counts are distinct canonical names, not actions. Missing previous names support only the volume arm. Final-extension or trailing-tilde removal, same-stem temporary-to-document/image completion, and the narrow Word save-via-temp pattern are volume-only. The completion suffix set is `.pdf`, `.tif`, `.tiff`, `.jpg`, `.jpeg`, `.png`; this covers scanner `.part` to `.pdf` completion without exempting `.tmp` to `.locked`. Changed extensionless names are volume-only with unresolved encryption status. Arbitrary uniform victim-specific extensions remain eligible. Late records replay from bounded disk history before the ratio is published.

Completeness is tracked per client/server/share on disk. A refusal for another group or loss of extra citations does not invalidate retained members. An incomplete group with at least 100 retained names changed to one extension remains high with an explicit lower-bound claim and unresolved ratio; the 80% ratio is asserted only for complete groups. If refusal bookkeeping cannot be retained or safely recovered, all groups become conservatively incomplete. Known positives remain reportable; incomplete below-threshold groups contribute honest limits.

## Service-name observations

`network.service_catalog` reads typed singular/plural DNS question names, TLS SNI and HTTP Host. Host ports are removed; bare IP hosts do not match. It uses case folding, an ASCII fast path, IDNA for non-ASCII/punycode names and exact or label-boundary suffix matching through a reversed-label trie. DNS syntax is required for consumed suffix labels; opaque labels to their left may contain underscores. Empty labels and overlong names are malformed. At most 1,024 names per record are evaluated, with an explicit partial-membership limit when capped. URI parameters, body text and TXT answers are not name keys.

`content/network/services.json` records each entry's suffixes, category, techniques, sources and licensing basis. Remote-access, tunnel and IDE entries are high severity; callback and file-sharing entries are medium. Every observation remains a lead. Claims describe a lookup or connection, never that software ran or transferred data.

The catalog includes ngrok agent control and regional tunnel names, MEGA API/storage, DNSLog/Ceye callbacks and sourced Pastebin/Paste.ee/Hastebin observations. GoTo coverage uses remote-support domains and excludes shared `logmein.com`/`logmeininc.com` collaboration infrastructure. It is an original factual compilation; no upstream catalog or prose is copied. DNSLog/Ceye entries cite Knownsec/FullHunt references.

Source groups fold by entry and internal address; fleet summaries stream membership and count distinct addresses. NAT and resolvers can hide multiple machines. Final rule output puts entries seen at one or two sources first; overall report ranking remains governed by the report policy.

The optional `approved_remote_access` list in `site/collection.yaml` accepts service catalog IDs or exact DNS suffixes. An ID covers its whole entry; a suffix covers that entry only within that label-boundary suffix and does not approve sibling suffixes. Approved observations produce one fleet lead, including a one-host fleet; unapproved observations retain per-source leads. Fleet membership streams with exact counts while event citations contain at most two witnesses; citation and retention shortfalls are explicit. A known approved positive retains a partial fleet lead if optional group state cannot be kept. Omission preserves the previous site-fact digest.

## HTTP attack observations

`network.web_attacks` uses one rule with seven explicit classes: SQL injection, cross-site scripting, path traversal/local-file inclusion, remote-file inclusion, OS command injection, server-side template injection, and known exploit/reconnaissance tool user agents. Sharing the bounded decoding pass and disk fold avoids seven copies of the same request. Each class retains its own finding identity and count. A second rule, `network.web_login_burst`, uses the existing disk-backed transaction-window engine.

| Typed fact | Zeek HTTP | Suricata HTTP | Arkime session |
|---|---|---|---|
| Request target | `uri` → `url.original` | `http.url` → `url.original` | `http.uri` → unordered `url.path` list |
| Method | `method` → scalar `http.request.method` | `http.http_method` → scalar `http.request.method` | Unordered `http.request.method` list; not paired |
| Response status | `status_code` → scalar `http.response.status_code` | `http.status` → scalar `http.response.status_code` | Unordered status list; not paired |
| User agent | `user_agent` → scalar `user_agent.original` | `http.http_user_agent` → scalar `user_agent.original` | Unordered `http.useragent` → `user_agent.original` list |
| Separate path/query | Typed `url.path` / `url.query`, when supplied, are inspected independently | Same typed-field contract | URI-list values are inspected independently |
| Request body/accounts | Body content unavailable; username only from the URI or a typed `user.name` | Same | No per-request account or outcome inference |
| Rules reading these facts | Both HTTP rules | Both HTTP rules | Request-shape rule only; never the login rate |

`rule_reads` admits only explicitly declared producers. The Arkime observation path does not change `protocol_record`'s transaction exclusion. A session containing an attack URI is a session-level observation; its status and user-agent lists cannot establish that the attack request received a particular response.

Request targets undergo at most two percent-decoding passes, plus-to-space conversion, HTML entity decoding and case folding. Strict UTF-8 rejects overlong encodings and invalid byte sequences. The bounds are 16,384 characters per URI, 2,048 per user-agent value, 128 values and 65,536 total input characters per record. Oversized, malformed or omitted inputs are counted and make inspection partial. Known positive values in a partially inspected record remain reportable. No body, serialized document or arbitrary message field is searched.

Patterns require token grammar: a `UNION SELECT` sequence with an operand, a quoted SQL clause, an executable HTML construct, path components reaching above the URI root, an explicit inclusion directive plus remote URL (or a file/path parameter plus remote script URL), a shell control token followed by a command, or template delimiters containing execution indicators. Ordinary isolated words, JSON, base64 tokens, in-root navigation and ordinary tracking parameters do not match these grammars. This is a positive-only, finite subset of attack syntax; encrypted traffic, novel grammars and attacks visible only in request bodies remain outside coverage.

Findings fold by source address, destination address and class. Canonical event identities are counted once on disk, independently of the two retained example citations; distinct inspected values after decoding/case folding and Arkime sessions are counted separately. These exact retained-observation counts do not claim distinct network requests across sensors or re-indexes. A disk refusal preserves the live positive and makes counts lower bounds. Retained examples omit the whole query when a recognized password, token or API-secret parameter is present, preventing encoded delimiters inside credentials from exposing their suffixes. URI userinfo is masked; ambiguous encoded authorities are omitted. Native references remain. Producer raw-evidence handling remains unchanged.

All classes remain **lead**, including a tool marker with a 2xx response. Neither a response status nor response size establishes exploit execution. Site-declared management sources receive an authorization note and retain their lane. User-agent markers are spoofable and configurable; a named tool may use an ordinary browser identifier.

The login rule observes at least **20 attempt raw references in a closed five-minute window**, grouped by source, destination, authentication path and sensor. This exceeds an ordinary person's few retries without claiming a universal brute-force threshold; NAT, broken automated clients and approved testing remain possible. It counts 401/403 responses, and POST requests receiving 200 as attempts because the response may be a re-served form. Ordinary GET 200 form retrievals, unrelated paths, redirects and Arkime lists do not count. Late records replay from disk, repeated/known account labels count exactly, and absent accounts share an explicitly unknown bucket. No status is treated as authentication success.

Grammar and licence sources are recorded in [`web_attacks_sources.json`](../../content/network/web_attacks_sources.json), with an [attribution notice](../../content/network/WEB-ATTACKS-NOTICE.txt) and the [Apache-2.0 licence](../../content/network/OWASP-CRS-LICENSE.txt). The reference corpora are [OWASP CRS](https://github.com/coreruleset/coreruleset) (Apache-2.0) and Sigma's [Suspicious User-Agents Related To Recon Tools](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_susp_useragents.yml) (DRL-1.1). Affected tool findings name Sigma authors Nasreddine Bencherchali (Nextron Systems) and Tim Shelton. Nuclei's additional factual marker comes from [ProjectDiscovery's documentation](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md).

Site-network declaration diagnostics are described in [Internal network coverage](network-coverage.md).
