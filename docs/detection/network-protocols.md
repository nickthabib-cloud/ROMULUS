# Network protocol contracts

Typed field origins name the source record and native field. Missing values remain missing. A recognized malformed application subrecord rejects its enclosing EVE record atomically and is counted as a normalization error. A protocol that is not implemented is counted as not normalized.

`detect.network_producers.protocol_record(event, family)` checks the exact family and a known producer identity. It does not prove that a particular record contains every field a rule needs. Rules must retain their field, outcome, identity and coverage checks. The helper accepts Zeek and Suricata protocol contracts; it excludes Arkime's unordered session sets from transaction rules.

`rule_reads(event, producers)` is the gate each network rule applies. The RPC administration, coercion and replication rules, the WinRM rule and the Netlogon and RPC enumeration rates read Zeek and Suricata records, since each needs only facts both sensors type alike: an RPC call by endpoint and operation names or by interface UUID and opnum, and an HTTP request in its flow's direction. Suricata records the interface beside the opnum for calls over SMB named pipes; a standalone DCERPC request record carries only the opnum, so its call is not classified and these rules do not judge it. The other network rules read Zeek only: the RDP rules (Suricata writes the server's responses as records of their own, without a typed request or response subtype, so the client cannot be told from the server), the NTLM rates (Suricata records no authentication outcome, so a successful logon would count as an attempt), the Kerberos rates (reply and error records may be written from the KDC's side), the requested-ticket-lifetime rule (Suricata does not record the requested till), the VNC rule (Suricata RFB records are not normalized) and the SMB admin-share executable rule (Suricata gives no cross-record file identity and direction). A rate that counts raw references keeps its count per sensor, so two sensors on one link do not double it; a rate that counts distinct members shares them across sensors.

## Producer and field matrix

Common available network fields are `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport` and `network.community_id`, when carried by the record. Suricata also preserves `suricata.flow_id`. These are sensor observations, not endpoint execution records.

The following table describes application fields in addition to that common tuple. Every listed field is conditional on the source providing it; a family is not a promise of complete visibility. Zeek's full native and shipper field tables are in `src/romulus/evidence/zeek_catalog.py`.

| Family | Zeek producer | Suricata producer | Arkime producer |
|---|---|---|---|
| `rpc_tx` | `rpc.endpoint`, `rpc.operation`, catalog-derived `rpc.interface_uuid`, `rpc.opnum`, `rpc.op_class` | `dcerpc`, including embedded SMB RPC: `rpc.interface_uuid`, `rpc.opnum`, `rpc.op_class` | No transaction contract |
| `smb_tx` | `smb.command`, `smb.action`, `smb.path`, `smb.share`, `smb.name`, `smb.prev_name`, version/status and file identity fields by log | `smb`: command, status, version, share/path/name/previous name, explicit rename/delete/create action, file size/FUID when present | Lists on `net_session`, never `smb_tx` |
| `ntlm_tx` | `ntlm.username`, `ntlm.domain`, `ntlm.hostname`, explicit `ntlm.success`, derived account/name fields | Separate SMB authentication child: username/domain/hostname, `source.hostname`, `user.name`, `user.domain`, `auth.target_account`; no success inferred from SMB status | Independent username/domain/workstation lists on `net_session` |
| `kerberos_tx` | request type, client/client name, service, ticket cipher and numeric etype, explicit error/outcome and request lifetime fields | `krb5`: `kerberos.request_type`, `kerberos.client`, `kerberos.client_name`, `kerberos.service`, ticket `kerberos.cipher`/`auth.encryption_type`; error message/code, KDC `auth.status` and `kerberos.error_source` only when attributable | Independent principal/service/realm lists on `net_session`; no ticket outcome, etype, lifetime or rate |
| `remote_session` | RDP and VNC protocol and negotiation metadata | RDP protocol, cookie, client build/name/channels, desktop dimensions, keyboard layout and client product ID when emitted | No transaction contract |
| `ldap_tx` | operation(s), object(s), argument(s), scope(s), base object(s), attributes, filter, result(s), bind type/version/message ID and observed result count by log | LDAP request/response operation, bind/search fields, scope/base object/attributes, serialized presence filter, explicit result(s); no inferred result count | Bind authentication type and bind-name lists on `net_session` |
| `app_tx` (SMTP) | `app.protocol`, `smtp.helo`, `smtp.mail_from`, `smtp.rcpt_to`, and message metadata | SMTP fields above; email from/to/cc/subject/message ID/user agent when emitted | No SMTP contract |
| `app_tx` (FTP) | protocol, command, argument, reply/code and data-channel fields | `ftp`/`ftp_data`: protocol/command/argument, single reply/code, passive flag and dynamic response port; multiple replies remain unpaired | No FTP transaction contract |
| `app_tx` (SNMP) | `snmp.version`, observed session counters and credential presence | SNMP version and credential presence; no session counters inferred from one PDU | No SNMP contract |
| `app_tx` (TFTP) | No TFTP log in the current Zeek catalog | Generic `app.protocol`, `app.command`, `app.arg`; no Zeek TFTP parity claim | No TFTP contract |
| `address_assignment` | DHCP address, name, MAC, lease and message-type fields | DHCP assigned/client/requested IP, client MAC, hostname, lease and message types | No DHCP contract |
| `net_alert`, `net_flow`, `dns_query`, `http_tx`, `file_transfer`, `tls_session`, `ssh_session` | Existing catalog contracts | Existing EVE alert/flow/netflow/DNS/HTTP/fileinfo/TLS/SSH contracts | Corresponding independent values on `net_session` only |
| `x509_certificate`, `asset_observed`, `sensor_health`, `ics_tx` | Existing catalog contracts | Not admitted by this producer helper | No transaction contract |
| `net_session` | Not produced | Not produced | One session with existing flow/DNS/HTTP/TLS/SSH fields plus the independent sets below; excluded by the transaction helper |

Suricata has producer identity `suricata-eve@1`; Arkime has `arkime@1`. Zeek retains its own producer epoch. Hunt manifests record all producer versions. A saved hunt using only the former shared network identity must be restarted; it cannot mix staged old IDs with newly fetched IDs.

### Suricata interpretation limits

A request/response transaction is one event. An SMB authentication or RPC subrecord gets its own typed family and identity with the enclosing raw reference. Candidate RPC interfaces are not multiplied into calls; multiple unpaired interface candidates leave classification unresolved.

Kerberos `ticket_encryption` on an AS/TGS reply is the issued ticket's encryption type. EVE `encryption` describes a different encrypted part and is not substituted for it. Names map to numeric etypes through the shared IANA/RFC table; [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961), [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) and [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) describe the algorithms and identifiers. KDC error attribution requires the failed AS/TGS request indication. Missing ticket cipher or error attribution cannot support the corresponding credential rule.

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
- Whole-name matches from `content/network/ransom_notes.json` created in at least 10 directories: lead lane, high severity.

Native Suricata 8 rename records do not themselves carry the share path: the serializer emits it on other SMB operation types. This rule does not join tree/session IDs across records. A rename without independently supplied share context is unresolved for this rule; the enriched Suricata fixture proves the typed integration only. Zeek SMB file records already supply the share path.

Counts are distinct canonical names, not actions. Missing previous names support only the volume arm. The narrow Word save-via-temp pattern stays outside extension evidence; other temporary filenames do not receive a blanket exception. Late records replay from bounded disk history before the ratio is published. A retention limit is reported; accepted volume lower bounds and already established positives remain reportable.

## Service-name observations

`network.service_catalog` reads only typed DNS question names, TLS SNI and HTTP Host. It uses case folding, IDNA conversion and exact or label-boundary suffix matching through a reversed-label trie. URI parameters, body text and TXT answers are not name keys.

`content/network/services.json` records each entry's suffixes, category, techniques, sources and licensing basis. Remote-access, tunnel and IDE entries are high severity; callback and file-sharing entries are medium. Every observation remains a lead. Claims describe a lookup or connection, never that software ran or transferred data.

Source groups fold by entry and internal address; fleet summaries stream membership and count distinct addresses. NAT and resolvers can hide multiple machines. Final rule output puts entries seen at one or two sources first; overall report ranking remains governed by the report policy.

The optional `approved_remote_access` list in `site/collection.yaml` contains service catalog IDs. It adds an approval note without lowering the lane. Omission preserves the previous site-fact digest. Disk or citation limits remain explicit, and a known positive retains a bounded source lead even if optional group state cannot be kept.
