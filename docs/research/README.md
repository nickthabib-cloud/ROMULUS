# Detection research register

Spec §7 *Detection breadth*. This folder documents the research data under `content/research/`. That data is the map of what ROMULUS should detect, what it already detects, and why each gap is a gap. It is a research and planning view: nothing in it is a detection result or proof of coverage (spec §1, *Truthful coverage*).

Round 1 is dated 2026-10-19 and is the work of the `detection-engineer`. It changed data and docs only, no code.

## Files

| Path | What it holds |
|---|---|
| `content/research/attack/enterprise/NN-<tactic>.yaml` | The register: one entry per ATT&CK Enterprise technique and sub-technique, grouped by the entry's first tactic in kill-chain order |
| `content/research/telemetry_families.yaml` | Vocabulary of telemetry families and their ROMULUS typed fields, with lab presence and normalizer status |
| `content/research/correlation.yaml` | Host↔network correlation catalog: join keys, confidence grades, prerequisites and 26 correlations |
| `content/research/tools.yaml` | Offensive and dual-use tool catalog (round 1: Linux and network tooling), behavior first |
| `content/research/lotl_linux.yaml` | Linux living-off-the-land catalog: binaries, abuse patterns and the context signals each rests on |
| `content/research/backlog.yaml` | The 25 highest-value new detections for lab telemetry, with draft selection cards |

## ATT&CK version and sources

- **Version:** ATT&CK Enterprise **v20.0**, as shown on attack.mitre.org on 2026-10-19 (227 techniques, 479 sub-techniques; the register holds all 706).
- **Sources:**
  - Technique IDs and names come from the site's technique list.
  - Tactic membership comes from the tactic pages and the enterprise matrix.
  - Linux and Network Devices platform membership comes from the v20 platform matrices.
  - Other platforms in an entry (Windows, macOS, cloud and so on) are recalled from earlier ATT&CK releases and are not verified.
  - No file was downloaded.
- **v20 changes that matter here:**
  - Defense Evasion is gone. Its place is taken by two tactics: **Stealth** (TA0005) and **Defense Impairment** (TA0112).
  - T1562 *Impair Defenses* no longer appears. Its content moved to:
    - T1685 *Disable or Modify Tools*, which now includes clearing Windows and Linux logs (T1685.005, T1685.006);
    - T1686 *Disable or Modify System Firewall*;
    - T1688 *Safe Mode Boot*;
    - T1689 *Downgrade Attack*;
    - T1690 *Prevent Command History Logging*.
  - T1070.001 and T1070.002 moved into T1685.
  - T1656 and T1672 became T1684 *Social Engineering* (.001 Impersonation, .002 Email Spoofing).
  - T1211 is renamed *Exploitation for Stealth*. T1552.003 is renamed *Shell History*.
  - New techniques include T1677 *Poisoned Pipeline Execution*, T1678 *Delay Execution*, T1679 *Selective Exclusion*, T1680 *Local Storage Discovery*, T1697 *Steal Application Specific Passwords*, T1700 *AI-Enabled Exfiltration*, T1059.013, T1213.006, T1027.018 and T1036.012.
- **Verification debt.** The spec requires ATT&CK mappings to be verified against a vendored copy of the official STIX data, and none is vendored yet. The membership above was read through a page summarizer. Before the coverage matrix is generated, reconcile the register against the STIX bundle, including platforms, data components and detection strategies, and the procedure examples the spec asks for. Vendoring the bundle needs owner approval (see *Open items*).

## Scope of fill (round 1)

An entry is **assessed** (all fields filled) when any of these holds:
- the technique has Linux or Network Devices in its v20 platforms;
- its tactics include Initial Access, Lateral Movement, Command and Control or Exfiltration;
- it is one of six Reconnaissance entries that existing rules map to (T1595, T1595.001–.003, T1590, T1590.002). Filling these goes slightly beyond the brief, so that the coverage those rules provide stays visible.

Every other entry is a **stub** with only `id`, `name` and `tactics`. A stub has been walked and listed but not assessed. It is never read as "not observable" or "covered".

## Register entry schema

Assessed entry:

```yaml
- id: T1059.004                 # ATT&CK ID; sub-techniques use the parent prefix
  name: Unix Shell              # v20 name (sub-techniques: the sub-technique's own name)
  tactics: [execution]          # every v20 tactic the technique belongs to, kill-chain order
  platforms: [Linux, macOS, ESXi]
  telemetry:                    # families from telemetry_families.yaml + the typed fields that would show it
    - family: auditd_exec
      fields: [process.executable, process.argv, process.ppid]
  lab_observable:
    status: yes | partial | no
    reason: ...                 # what lab records show it, and whether a normalizer emits the fields today
  rules: [host.web_service_spawns_interpreter]   # existing rules that detect a procedure of this technique
  disposition:
    status: covered | planned | needs_telemetry | not_observable_by_design | deferred
    reason: ...
  priority: P1 | P2 | P3 | P4
  detection_ideas: [...]        # behavior-first; "BL-nn" refers to backlog.yaml
  correlation: [...]            # host<->network joins; "COR-nn" refers to correlation.yaml
  pivots: [...]                 # what an investigator should look at next
```

Field semantics:

- **`telemetry`** lists every family that could observe the technique on any mission network, not only the lab's families. Field names are ROMULUS typed fields. For lab families they are checked against the vocabulary. For families that are absent from the lab, they are descriptive until a field contract exists.
- **`lab_observable`** answers whether the records in the lab show the technique today. `partial` means some procedures, some fields, or records that exist but are not normalized. The reason always says which.
- **`rules`** lists every existing rule that detects a procedure of the technique, whether or not that rule's own ATT&CK metadata names the technique. Every technique a rule claims in its metadata appears here. The disposition reason states when a claimed mapping is context only (for example, `host.firewall_rule_change_command` → T1498).
- **`disposition`** (the brief's vocabulary). Mapping to spec §7 wording:

  | Status | Meaning | Spec §7 wording |
  |---|---|---|
  | `covered` | At least one active, fixture-tested rule detects a core procedure. The reason names what remains uncovered. | "rule active" / "covered by <rule>" |
  | `planned` | A detection is designed for telemetry the lab has today. It may need a normalizer extension for records that are already present (for example auditd SOCKADDR, EVE tls fields). | "planned" |
  | `needs_telemetry` | Observable in a family a CPT may meet, but not in the lab: Windows, Zeek, identity, cloud, device logs, or audit rules the lab may not have. The reason names the family. | "not observable in supported telemetry (why)", or "planned" once the family is supported |
  | `not_observable_by_design` | The behavior happens off the defended network or below the telemetry floor, such as firmware or in-process logic. The reason says what indirect consequence, if any, is covered elsewhere. | "not observable in supported telemetry (why)" |
  | `deferred` | Observable, but deliberately not built now (low value, ubiquitous benign use, or subsumed by another entry's detection). The reason says why. | "deferred (why)" |

  `requested` is reserved for analyst detection requests from the catalog page (spec §7, tier 2). No entry uses it yet.
- **`priority`** is the order in which to build, not severity:
  - `P1`: high value, general across mission networks, and buildable on lab telemetry now or after one normalizer extension;
  - `P2`: high value but needs more prerequisites, or is narrower;
  - `P3`: useful but moderate;
  - `P4`: low value, edge case, or not observable.
- **`detection_ideas`** are behavior-first. Ideas that interpret text (argv, messages, user agents) carry "positive-only" (ADR-004). Ideas that rest on kernel-recorded or typed network fields can assure negatives once coverage is profiled.

## Other schemas

- **`telemetry_families.yaml`**: `id`, `title`, `typed_family`, `lab` (present/absent/unverified), `normalizer` (normalized/partial/proposed), `fields.normalized` (emitted by `lab-ecs@1` today) and `fields.proposed`, and `notes` on outcome and identity semantics.
- **`correlation.yaml`**:
  - join keys K1–K8;
  - confidence grades: `exact` (network↔network only), `tuple_strong`, `tuple_partial`, `temporal`;
  - prerequisites P1–P4: host alias table, clock-skew estimate, sensor visibility map, auditd_net normalizer;
  - per correlation: claim wording, host and network sides (family plus fields), join keys, confidence, lab feasibility, value, techniques, and the backlog items that build it.

  Every grade except `exact` is a hypothesis under spec §1, and its wording says so.
- **`tools.yaml`**:
  - per tool: category, dual-use flag, ATT&CK software ID (null if not an ATT&CK entry), platforms, techniques;
  - `behaviors`: each with telemetry, the detection that covers it, and a disposition;
  - `leads`: names, argv tokens, default ports, protocol markers. Leads are positive-only and never the basis of a negative.
- **`lotl_linux.yaml`**: shared `context_signals` (lineage, account, args, effect, rarity, time, chain). Per binary group, abuse `patterns`, each with techniques, the signals it rests on, detection, disposition, and benign uses.
- **`backlog.yaml`**: rank, rule type, assurance (negative-capable or positive-only), proposed lane and severity, techniques, prerequisites, and a one-paragraph draft selection card (claim, telemetry, fidelity, benign causes, next pivot). A backlog card is not a rule. A rule built from it still needs the full §9 card, a typed predicate, a retrieval superset, fixtures and a review.

## Round 1 counts

The register holds 706 entries: 397 assessed and 309 stubs.

| Disposition | Entries |
|---|---|
| covered | 23 |
| planned | 234 |
| needs_telemetry | 78 |
| not_observable_by_design | 22 |
| deferred | 40 |
| stub (not yet assessed) | 309 |

- Lab observability of the 397 assessed entries: 112 yes, 197 partial, 88 no.
- Priority: 51 P1, 99 P2, 130 P3, 117 P4.
- Other catalogs: 26 correlations, 25 backlog items, 48 tool entries, 32 LOTL binary groups with 56 abuse patterns.

"Covered" counts techniques with at least one active rule for a core procedure. It is not a recall claim; recall and precision belong to the eval-custodian (spec §15).

## Workflow

1. **New content or a changed rule.** When a rule is added or changed:
   - update `rules` and `disposition` for every technique it detects;
   - record in the reason what the rule does not cover;
   - add the technique to the rule's ATT&CK metadata only if the rule detects it, since ATT&CK on a finding is context, never proof.
2. **Looked at, not covered.** Any technique examined and not covered gets a disposition and a reason. Nothing is skipped silently.
3. **New ATT&CK release.** Reconcile IDs, names, tactics and platforms against the new STIX bundle. Revoked or deprecated techniques move to their successors, with the old ID noted in the reason. Re-check every rule's metadata.
4. **New telemetry family.** Add it to `telemetry_families.yaml`, then revisit every `needs_telemetry` entry whose reason names it.
5. **Stubs.** Later rounds fill them, in this order: Windows (Security, Sysmon, PowerShell) for the Execution, Persistence, Privilege Escalation, Credential Access and Discovery stubs; then identity and cloud; then macOS. ATT&CK for ICS gets its own register under `content/research/attack/ics/`, keyed on Zeek ICSNPP and Malcolm. Its wording must separate "request observed" from "state changed", and it must never suggest active probing.
6. **Validation.**
   - Round 1 was checked with a one-off script that was not committed, because the brief allowed no code. It checked:
     - every v20 ID is present exactly once;
     - tactics and names match the transcription;
     - the Linux and Network Devices platform flags are applied;
     - every assessed entry has every field and a legal enum value;
     - rule IDs exist in `m1-pack@2`, and every rule's own ATT&CK claims appear in the register;
     - telemetry family IDs exist, and lab-family fields are in the vocabulary;
     - COR, BL and technique references resolve across all files.
   - A committed validator and the generated `docs/detection/ATTACK_COVERAGE.md` (spec §7, checked in CI) are code work for the lead.

## Corpus licenses (for later harvest rounds)

Round 1 used ATT&CK (read on the website) and general knowledge of GTFOBins and the CISA living-off-the-land guidance, reimplemented and not copied. Licenses as recalled; confirm each one at harvest time, and keep content under an incompatible license as reference only:

| Corpus | License (to confirm) |
|---|---|
| MITRE ATT&CK | ATT&CK Terms of Use (royalty-free, attribution) |
| SigmaHQ | Detection Rule License 1.1 |
| Elastic detection-rules | Elastic License 2.0 |
| Splunk security_content | Apache-2.0 |
| MITRE CAR | Apache-2.0 |
| Atomic Red Team | MIT |
| GTFOBins, LOLBAS | GPL-3.0 |
| ET Open | GPL-2.0 (some BSD) |
| CISA advisories | US Government work |

## Open items

- **Vendored STIX.**
  - Needed to verify v20 membership and platforms.
  - Needed to record ATT&CK data components or detection strategies, and procedure examples (spec §7 item 1).
  - Needed to re-verify the ATT&CK software IDs in `tools.yaml`, which were transcribed through a page summarizer.
  - Downloading the bundle needs owner approval.
- **Stale rule metadata (outside this round's scope).** `host.firewall_rule_change_command` still claims T1562.004, which was revoked in v20; the successor is T1686. Its T1498 claim, and the T1036.005 claim of the two temp-directory rules, are context only (see their entries).
- **Lab facts to confirm** through the SourceProfile:
  - which audit rules exist on each host (open/write/unlink, ptrace, init_module, setxattr, socket(AF_PACKET), USER_*/ADD_USER/CONFIG_CHANGE records);
  - whether EVE fileinfo carries magic or hashes;
  - whether EVE tls/ssh carry JA3/JA4/HASSH;
  - whether Arkime exposes ja4.
