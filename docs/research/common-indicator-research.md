# ROMULUS common behavioral indicator research corpus

**Date:** 2026-10-15  
**Status:** Authoritative research input with generated runtime packs and an operator inventory.  
**Size:** 3,863 candidate records: 902 curated behavioral indicators, 485 LOLBAS capability records, 731 GTFOBins capability records, and 1,745 indexed ATT&CK detection analytics.

## Objective

Build a broad anomaly-first inventory that helps ROMULUS notice suspicious activity even when it cannot yet assemble a complete attack path. The corpus treats a process, command, file, API action, or network event as a lead. It raises confidence when the lead targets a sensitive object, occurs in a privileged or rare context, or connects to an independent signal on the same actor, asset, object, or destination.

## Main research conclusions

1. **Single exact markers are only one layer.** Some events are independently strong, such as reading `/etc/shadow`, disabling audit collection, adding a cloud access key, or creating a privileged container. Many common utilities are weak until their arguments, target, parent, user, or network behavior is known.
2. **Relationships should drive escalation.** Download then execute, enumerate then elevate, read credentials then authenticate remotely, archive then upload, and disable security then run a payload are stronger than any isolated member of the sequence.
3. **Rarity is context.** A first-seen process, domain, user-host pair, or cloud API helps prioritize concrete suspicious behavior. It should not independently become a malicious finding.
4. **Coverage must be explicit.** A non-match is meaningful only when the required event source, fields, time range, and sensor health were present.
5. **Published dual-use catalogs need argument-aware translation.** LOLBAS and GTFOBins are excellent research indexes. Alerting on process names alone would produce large amounts of noise.

## Logical priority model for ROMULUS

| Signal class | Default treatment | Elevate when |
|---|---|---|
| Concrete credential access, security impairment, privileged persistence, destructive change | High | Event is successful and actor or target is unexpected |
| Same-event compound with execution or sensitive target | Medium to high | Exact arguments, target, parent, and privilege align |
| Short sequence or cross-source relationship | High | Entities match and timing is tight |
| Common dual-use binary or Unix utility | Low | Published abuse arguments or a strong contextual relationship is present |
| First-seen or rare behavior | Low | A concrete suspicious behavior occurs on the same entity |
| Trusted exact indicator | Critical lead | Provenance and freshness are valid; still describe the observation accurately |

## Romulus support assessment

- **Direct rules:** All 549 are executable. Seventy-three run active and 476 run observe only with a score ceiling.
- **Sequences:** 26 of 89 have reviewed stage, order, window, and join semantics. The other 63 are reference only.
- **Aggregates:** 18 of 206 have reviewed filters, groups, windows, sample minimums, and thresholds. The other 188 are reference only.
- **Baselines:** 43 of 58 have reviewed scopes, warm-up, values, and deviation semantics. The other 15 are reference only.
- **Capability context:** 1,216 LOLBAS and GTFOBins records enrich exact cited executables without changing priority or disposition.
- **ATT&CK context:** 1,745 analytic references remain research context; the pinned 697-technique catalog supports bounded planning and mapping.

## Curated behavior inventory

The maintained plain-language list is [indicator-priority-inventory.md](indicator-priority-inventory.md). It contains every curated behavior name, research priority, and current runtime state without duplicating query JSON or the full machine-readable conditions.

## Source-derived capability indexes

- **LOLBAS:** 485 command/use-case records from 245 Windows binaries, scripts, and libraries. Each record requires argument and context matching.
- **GTFOBins:** 731 executable/function records from 478 Unix executables. Each record requires privilege, function, target, or command context.
- **MITRE ATT&CK:** 1,745 detection analytics across 697 Enterprise techniques and sub-techniques, indexed to the pinned local catalog.

## Recommended conversion order

1. Replay active direct, sequence, aggregate, and baseline translations against representative benign and authorized attack-simulation telemetry.
2. Add translations only when fields, joins, time windows, sample sizes, and thresholds are explicit and testable.
3. Expand normalized identity, cloud, Kubernetes, process, privilege, file-operation, and network-direction fields where real source mappings demonstrate a need.
4. Tune environment-specific thresholds from completed hunts while excluding evidence already cited by candidates or findings.
5. Keep capability and ATT&CK records bounded and evidence-linked; they must never raise a score by themselves.

## Research sources

- **MITRE_ATTACK:** [MITRE ATT&CK Enterprise v19.2](https://attack.mitre.org/) — Technique, tactic, platform, detection-strategy, and analytic coverage backbone.
- **SIGMA:** [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma) — Generic log detections, hunting rules, log-source requirements, severity, and false-positive patterns.
- **ELASTIC_RULES:** [Elastic detection-rules](https://github.com/elastic/detection-rules) — ECS-oriented endpoint, identity, cloud, and network rule patterns and hunt queries.
- **MICROSOFT_SYSMON:** [Microsoft Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon) — Windows process, network, file, registry, image-load, process-access, and tampering telemetry.
- **WINDOWS_AUDIT:** [Microsoft Windows security auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) — Windows process and authentication event correlation.
- **LOLBAS:** [LOLBAS](https://lolbas-project.github.io/) — Windows signed binary, script, and library capabilities that require command-line and context-aware detection.
- **GTFOBINS:** [GTFOBins](https://gtfobins.org/) — Unix executable capabilities under shell, SUID, sudo, capability, file, and network contexts.
- **ATOMIC_RED_TEAM:** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — Portable ATT&CK-mapped behaviors for later validation in an authorized lab.
- **REDHAT_AUDIT:** [Red Hat audit system guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening) — Linux process, syscall, identity, and sensitive-file audit coverage.
- **APPLE_ES:** [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) — macOS process, file, task-port, authentication, and interprocess event coverage.
- **ZEEK:** [Zeek common logs](https://docs.zeek.org/en/current/reference/logs/index.html) — Connection, DNS, HTTP, TLS, file, SMB, SSH, RDP, and protocol metadata.
- **SURICATA:** [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) — Network alerts, protocol records, flows, files, drops, and protocol anomalies.
- **KUBERNETES_AUDIT:** [Kubernetes audit logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) — Kubernetes API verbs, actors, resources, request bodies, and response status.
- **AWS_CLOUDTRAIL:** [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) — AWS actor, source, API action, resource, request parameter, and outcome evidence.
- **AZURE_ACTIVITY:** [Azure Activity Log](https://learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log-schema) — Azure administrative, security, policy, role, resource, and control-plane changes.
- **ENTRA_LOGS:** [Microsoft Entra activity logs](https://learn.microsoft.com/entra/identity/monitoring-health/overview-monitoring-health) — Identity sign-in, audit, provisioning, application, and service-principal activity.
- **GCP_AUDIT:** [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) — Google Cloud admin, data access, system, and policy-denied activity.

## Files

- `docs/research/common-indicator-corpus.json` — complete machine-readable corpus.
- `docs/research/indicator-priority-inventory.md` — generated plain-language priority and runtime-status list.
- `docs/research/common-indicator-research.md` — this research rationale and source guide.
