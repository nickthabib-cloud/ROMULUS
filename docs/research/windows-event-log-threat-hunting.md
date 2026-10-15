# Windows Event Log Threat Hunting: Coverage and Priorities

**Research date:** 2026-10-15  
**Scope:** Windows Security, PowerShell, Sysmon, Defender, and supporting telemetry for ROMULUS hunts.  
**Use:** Defensive detection design and telemetry coverage review. Event IDs are not treated as standalone proof of compromise.

## Executive view

Windows event logs are among the strongest sources for reconstructing who authenticated, what process started, which command line was used, what persistence changed, and whether security controls or logs were altered. Their value comes from joining events across a host and time window. A process event by itself often says *what ran*; logon, task, service, file, registry, network, and security-control events help explain *who caused it, how it persisted, what it touched, and what happened next*.

The most important coverage caveat is that Windows does not emit every useful field by default. Event 4688 exists only when process-creation auditing is enabled, and its command line is empty unless the separate command-line inclusion policy is enabled. PowerShell Script Block Logging is a policy choice. Sysmon is disabled until installed and configured; its event filters determine which event families actually exist. File and registry object-access events require both audit policy and matching object SACLs. A missing event therefore means “not observed in available telemetry,” not “did not happen.”

For ROMULUS, this means Windows process and command indicators can run over 4688, Sysmon process-create, and PowerShell script-block records only when field normalization and collection include those channels. Stronger hunt paths require event identity fields such as logon ID, user, process ID, parent process, asset, and time. We should report unavailable fields and channels as coverage gaps rather than lower the detection score or claim a clean result.

## Telemetry layers

| Source / channel | High-value events | What they show | Collection prerequisites and caveats |
|---|---|---|---|
| **Windows Security** | 4688; 4624, 4625, 4648, 4672; 4697; 4698–4702; 4719; 1102; account/group changes; 4768, 4769, 4771 | Process creation; successful/failed logons; explicit credentials; privileged logons; service and scheduled-task changes; audit-policy changes and log clearing; account/group changes; Kerberos ticket activity | Configure the matching Advanced Audit Policy subcategories. Event 4688 command lines require **Include command line in process creation events** in addition to Audit Process Creation. 4768/4769/4771 are most useful on domain controllers. Source IP and some identity fields vary by authentication protocol and event version. |
| **PowerShell Operational** | 4103, 4104 | Cmdlet/module activity and processed script-block content | Enable module or script-block logging by policy. 4104 is verbose and can contain sensitive values. Protect stored event content and restrict access; Microsoft recommends Protected Event Logging where appropriate. |
| **Sysmon Operational** | 1, 3, 8, 10, 11, 12–14, 22, 25 | Process creation; process network connection; remote-thread creation; process access; file and registry changes; DNS; process tampering | Sysmon must be installed/enabled and configured. Event filters can include or exclude event types. Network-connect (3), image-load (7), and process-access (10) can be high-volume or noisy; configuration and tuning affect coverage. |
| **Microsoft Defender Operational** | 1116, 1117, 5001, 5007 | Malware/threat detection and response; real-time protection disabled; configuration changes | Interpret with Defender product state, policy, and action outcome. A configuration-change event is a review trigger, not proof of malicious intent by itself. |
| **Object access / WFP** | 4657, 4663; 5140, 5145; 5154–5159 | Registry or file access; network share access; allowed/blocked connections and listening/bind activity | File and registry auditing requires a matching SACL. WFP connection auditing can be very high-volume. Use targeted objects, process identity, and host baselines. |

Microsoft describes Security 4688 as the process-start event and documents the additional policy needed to record its command line ([4688 details](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688), [command-line auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)). The Security log's Advanced Audit Policy settings define which categories generate events and call out event volume and object-SACL requirements ([Advanced Audit Policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)).

PowerShell 4104 records script blocks when Script Block Logging is enabled; 4103 is associated with module logging. The events may capture sensitive content, so ingestion and access policy matter ([PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1), [PowerShell logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)).

Sysmon records events to `Microsoft-Windows-Sysmon/Operational`, but the event filters are configurable. Microsoft documents Process Create (1), Network Connect (3), CreateRemoteThread (8), ProcessAccess (10), DNS Query (22), and Process Tampering (25), including noise caveats for ProcessAccess and image loads ([Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events), [Sysmon configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files), [enable and configure Sysmon](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)).

## Hunt patterns and priority

Priority below means *how quickly an analyst should examine the behavior in context*. It is separate from confidence that a compromise occurred.

| Priority | Behavior pattern | Useful evidence and correlation | Noise / interpretation |
|---|---|---|---|
| **High, immediate review** | Security audit log cleared (1102), system audit policy changed (4719), or a logging service/configuration changed | Security event plus nearby 4688/4104 commands, account/session, host, and any other event channel that remains available | These are security-control changes. Confirm maintenance or authorized policy deployment, then check for nearby execution and collection gaps. |
| **High, immediate review** | Sysmon detects process tampering (25) or remote-thread creation (8) | Source and target process, hashes/signatures, process ancestry, process-access (10), and subsequent network or credential-access activity | Low-frequency/high-relevance in many configurations, but verify the Sysmon version, configuration, and source/target process context. |
| **High, conditional** | New service (4697) or scheduled task create/update (4698/4702) with an unusual binary, task action, actor, or timing | Creator identity/logon ID; service/task path and command; 4688 or Sysmon 1 execution after registration; file/registry and network events | Software deployment and endpoint management also create tasks and services. Elevate when the path, principal, action, or follow-on process is unusual. |
| **High, conditional** | PowerShell or signed utility performs encoded, hidden, remote-download, proxy-execution, or defense-impairment behavior | 4688/Sysmon 1 command line and parent; 4104 script block; 4103 module activity; Sysmon 11 file creation; Sysmon 3 network connection | PowerShell and signed utilities are common administration tools. The behavior/arguments, parent, user, target, and outcome matter more than the executable name alone. |
| **High, conditional** | Credential-store or LSASS access followed by a new privileged or remote logon | Sysmon 10 source/target process; 4663 only where the relevant SACL exists; 4672; 4624/4625 and shared account/logon identifiers | Process-access is noisy and some access is legitimate security software. Confirm target process, access type, actor, session, and subsequent authentication. |
| **High, conditional** | Unexpected account or privileged-group change | 4720/4722/4724 and group-change events such as 4728/4732; correlate actor, target account/group, 4672, 4624, and later use of the new identity | Domain-controller placement and audit policy matter. Approved identity lifecycle and admin changes are expected alternatives. |
| **High, conditional** | Kerberos authentication pattern differs sharply from the account/host baseline | 4768/4771 failures and 4769 service-ticket requests on DCs; compare account, client address, service, encryption fields, rate, and successful 4624 activity | 4769 volume can be very high. Individual ticket events are not suspicious without account, service, rate, encryption, or peer-group context. |
| **Elevated lead, validate promptly** | `nmap`, `nc`/netcat, `socat`, and similar dual-use tooling appears unexpectedly | Process creation and full arguments; parent process; user/session; subsequent Sysmon 3 or WFP 5156 connections; destination fan-out; asset role and authorized scanner/deployment inventory | Keep the tool above routine baseline when unexpected, but do not call a tool name alone malicious. ROMULUS should show a high-priority lead and raise confidence when the command, actor, destinations, and follow-on actions line up. |
| **Context / aggregate** | Repeated 4625 failures, many destinations, broad share access, or unusual outbound volume | Group on source/account/host/process and a time window; link failures to later success, or process creation to Sysmon/WFP connections | Single failures and single connections are common. Alert on rates, distinct targets, role mismatch, success after failure, and deviation from the host's normal role. |

Microsoft's event documentation supports the correlation fields: 4624 includes logon type, logon ID, process, source address, and a Logon GUID useful across related events; 4625 includes failure status/substatus and recommends looking at repeated failures and account/logon-type context ([4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)). Security audit guidance identifies task creation and service installation events, and describes log-clearing and policy-change events ([Advanced Audit Policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration), [events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)).

MITRE's Windows scheduled-task detection strategy demonstrates why task registration, process execution, file creation, and registry changes should be linked with a time window and user/task context, rather than treating one event ID as a complete attack path ([DET0441](https://attack.mitre.org/detectionstrategies/DET0441/)). Microsoft documents Defender Antivirus detection and action event IDs, including 1116 and 1117 ([Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)).

## Relational signatures to build

The following are defensive correlation shapes. The sequence is evidence to investigate, not an assertion that each stage is always malicious.

1. **Process launch to network activity:** 4688 or Sysmon 1 → Sysmon 3 or WFP 5156. Join on host and process identifier; retain user/session and parent process. A process-name match for `nmap`, `nc`, or `socat` plus many distinct destinations is a stronger lead than either fact alone.
2. **Remote logon to persistence:** 4624 (especially a remote/network logon type) → 4697 or 4698/4702 → 4688 or Sysmon 1. Join by host, account/logon ID where present, task/service action, process ancestry, and bounded time.
3. **PowerShell content to payload and connection:** 4688/Sysmon 1 → 4104/4103 → Sysmon 11 → Sysmon 3. Correlate the script host and process lineage; do not assume a script-block fragment and nearby file event share a cause without an identity/process/time join.
4. **Credential access to use:** Sysmon 10 or a targeted sensitive-file event → 4672 or a new 4624 → later remote execution/persistence. Match the same host/account/session where telemetry permits.
5. **Defense impairment to suspicious activity:** 1102/4719, Defender 5001/5007, or relevant process command → suspicious 4688/Sysmon 1, 4104, or authentication/network activity. Include a telemetry-health gap as supporting evidence, not as a substitute for the behavior.
6. **Kerberos failure/spray to success:** repeated 4771 or 4625 grouped by source and target accounts → successful 4624/4768. Use distinct-account counts, rate, result codes, and account role; avoid a simple fixed count without environment baselines.

The exact join keys must be checked against the ingested event schema. Preferred keys are `host.name`, `user.name`/target user, `winlog.event_data.TargetLogonId` or `SubjectLogonId`, `process.entity_id`/PID and parent PID, destination address, object path, and normalized event time. PID-only joins must be bounded by host and time because PIDs are reused. Logon ID and GUID fields can be missing or version-dependent; absence should lower coverage, not be filled by guesswork.

## ROMULUS coverage assessment

The 902-record corpus has **106 Windows endpoint direct indicators**, covering command lines and sensitive paths. The Windows command records explicitly expect Sysmon Event 1 or Security 4688 with command-line collection. ROMULUS now maps common Winlogbeat/Windows event fields, including process command lines, PowerShell script-block text, logon IDs, account names, process IDs, task/service fields, provider, and channel. A separate set of **19 source- and channel-aware Windows event rules** covers Security, Sysmon, PowerShell, and Defender event families; it is separate from the 902 corpus count.

The live runtime combines the 63 original catalog rules, 549 compiled direct corpus rules, and 19 Windows event rules. Across the 902 curated behaviors, 636 have executable semantics: 549 direct predicates, 26 sequences, 18 aggregates, and 43 baselines. The other 266 remain reference only with structured translation gaps. The Windows event pack has direct predicates for 1102/4719, 4697/4698/4702, 4624/4625/4648/4672, account/group changes, Kerberos events, PowerShell 4104, Sysmon 8/10/25, and Defender 5001/5007. Sequence matches require separate time-bounded evidence and declared joins; aggregate matches require explicit groups and thresholds; baseline leads require completed-hunt history and warm up.

The corpus also includes direct tool leads for `nmap`, netcat, and `socat` at **high** priority. These are active high-priority leads, and known Windows/Linux platform metadata is used to avoid matching an OS-specific rule against a clearly different endpoint. Their existence is not proof of malicious intent. Confidence should rise when the full command, user/session, process lineage, and Sysmon or WFP network fan-out agree.

## Implementation implications

- Preserve all 902 curated records and distinguish loaded, executable, executed, matched, partial, observe only, and reference only in runtime coverage.
- Activate rules only when their source, fields, joins or groups, time window, sample size, and threshold are exact. Keep untranslated records visible with structured missing-semantics reasons.
- Treat `nmap`, netcat, and `socat` as high-priority investigative leads; require command/context or related network behavior before a customer-visible conclusion.
- Add Windows semantic aliases for provider, channel, event data, user/session, process IDs, task/service, logon type, and PowerShell script-block text without rewriting raw evidence.
- Add event-source identity to rules: event ID alone is insufficient because IDs can be reused across providers/channels.
- Distinguish “no matching event” from “required audit policy, provider, field, or SACL was not available.”
- Prioritize a small, high-value event set first, then expand coverage through source-backed, versioned definitions and replay against representative benign/authorized data.
- Record the audit policies and Sysmon configuration version/filters that were active for each hunt, if the source provides that metadata.

## Primary references

- [Microsoft: Security auditing event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft: Command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Microsoft: Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft: Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft: Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: Audit Logon](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-logon)
- [Microsoft: PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
- [Microsoft: PowerShell logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)
- [Microsoft: Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft: Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
- [Microsoft: Enable and configure Sysmon](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft: Windows Filtering Platform auditing](https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging)
- [Microsoft: Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [MITRE ATT&CK: Detection of suspicious scheduled task creation and execution on Windows (DET0441)](https://attack.mitre.org/detectionstrategies/DET0441/)
- [Microsoft Sentinel: Windows Security event ID reference](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference)
