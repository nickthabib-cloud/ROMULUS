# ROMULUS Elasticsearch DSL Search Matrix

**Reviewed:** 2026-10-15  
**Purpose:** document the source selectors, behavior signatures, query format, and validation changes used by ROMULUS when planning Elasticsearch searches.

## How the DSL reaches the search

ROMULUS gives the planning LLM the available field names, index class, and mapped field types. It also gives the LLM a DSL pattern and these rules:

- `bool.filter` holds exact source selectors such as event ID, provider, channel, or dataset.
- `bool.must` holds behavior content that must occur in the same event document.
- `bool.should` with `minimum_should_match: 1` means one of the listed alternatives can match.
- Exact selectors use `term` or `terms` on keyword or numeric fields.
- `match_phrase` is used for `text` and `match_only_text` fields.
- A bounded `*literal*` wildcard is used for substring searches on indexed keyword-family fields. Embedded wildcard characters are escaped and unbounded patterns are rejected.
- ROMULUS adds the required hunt time range after validating the LLM's clause. The LLM is told to return a clause object, not an Elasticsearch request body.
- A native query is checked against the allowlisted DSL and each target index's mapping metadata. If it fails those checks, ROMULUS compiles the provided selectors deterministically for that index instead.

Illustrative PowerShell Script Block query:

```json
{
  "bool": {
    "filter": [
      { "term": { "winlog.event_id": "4104" } },
      { "term": { "winlog.provider_name": "Microsoft-Windows-PowerShell" } },
      { "term": { "winlog.channel": "Microsoft-Windows-PowerShell/Operational" } }
    ],
    "must": [
      { "wildcard": { "winlog.event_data.ScriptBlockText": {
        "value": "*FromBase64String*",
        "case_insensitive": true
      } } }
    ]
  }
}
```

The field names in an actual query must exist and be searchable in the connected deployment. The example uses Elastic Windows integration mappings; ROMULUS supplies a type-appropriate example from the live host mapping when those fields are present. It avoids `event.original` when the mapping reports that field as unindexed.

## Search matrix inventory

The checked-in `search_matrix_catalog.json` contains **118 behavior signatures in 10 signature sets**, attached to **13 source families**. Signatures are combined with the source/event selectors below. A query is only generated when required selector and behavior fields are mapped and searchable on that index.

| Platform | Event/source family | Behavior coverage |
|---|---|---|
| Windows | PowerShell Operational, event 4104 | Encoded/decoded content, downloads, dynamic execution, AMSI/logging tampering, credential access, discovery, persistence, log clearing, and multi-clause script behavior |
| Windows | Security 4688 and Sysmon 1 | Scanners and network tools, proxy/relay tools, remote execution, encoded PowerShell, LOLBins, transfer, credential dumping, defense evasion, account discovery, persistence, and remote-share access |
| Windows | Sysmon 3 | Network connections attributed to scanners, netcat/Socat, shells, remote tools, selected ports, and literal-address destinations |
| Windows | Security 4697 | Service image paths, shells, remote paths, suspicious parameters, network utilities, and account context |
| Windows | Security 4698/4702 | Task action shell/script hosts, encoded/hidden commands, download-and-execute, writable or remote paths, utilities, and tampering |
| Windows | Security 4624/4625/4648 | Failed/successful logon context and explicit credential use |
| Linux | `auditd.log` / `auditd_manager.auditd` | Process execution, discovery/utilities, shells, transfer tools, credential access, persistence, sensitive-file access, and selected syscalls |
| Linux | `system.auth` | SSH and sudo authentication/command context |

Tool names such as `nmap`, `socat`, `netcat`, `ncat`, and `nc` are intentionally ranked as **high-priority leads** in relevant process/network/service/task contexts. Their presence alone is not treated as proof of compromise; surrounding command, parent, event, account, destination, and host context still matters.

## Bounds and interpretation

- The matrix is compiled per index mapping so one index's field types do not silently determine another index's query. Identical compiled queries can share an index target list.
- Up to four related signatures are grouped per DSL batch. The current per-hunt matrix cap is `min(32, max(1, max_tool_calls // 4))`; the global scheduler can execute fewer searches when its total call budget or other required work takes precedence.
- Matrix batches retain their critical/high/medium/low priority. High-priority matrix batches (including relevant `nmap`, `socat`, `netcat`, and `nc` contexts) are scheduled ahead of the broad behavior-catalog batches, while trusted indicators and critical findings retain their higher scheduler rank.
- Missing mappings are recorded as a field-mapping gap instead of broadening to an unbounded query.
- `bool` clauses correlate fields in one document. They do not prove that separate events happened in order. Multi-event attack paths require event correlation or sequence analytics; the matrix's same-document combinations should not be described as a confirmed attack path.
- Leading wildcards can be expensive and can be disabled by Elasticsearch settings. ROMULUS limits them to bounded literal patterns and puts them behind source/event selectors. `case_insensitive` wildcard support requires Elasticsearch 7.10 or later.
- A compiled query that returns zero hits only weakens a hypothesis when the relevant event source is present, indexed, and in scope.

## Query quality fixes recorded

1. **Type-aware operators:** previous behavior signatures could send `match_phrase` to keyword fields. Compilation now selects full-text, exact, or wildcard operators from mapping types.
2. **Searchability checks:** fields with `index: false`, non-searchable types, or absent mappings are skipped or rejected. In particular, ECS `event.original` is not assumed to be searchable.
3. **Substring semantics:** keyword body fields use bounded substring wildcards rather than `match_phrase`; text fields retain analyzed phrase matching.
4. **Literal safety:** the earlier hex-encoded `prefix` fallback was removed because it did not match normal readable event text. Literal wildcard metacharacters are escaped and validated.
5. **Event plus content:** the matrix combines event/provider/channel/dataset selectors with behavior predicates, which keeps a Windows event-ID query from matching unrelated log text.
6. **Native-query fallback:** a DSL query that is structurally valid but mismatched to current mappings now falls back to the deterministic selector query when those selectors are usable.
7. **Exact source fields:** dataset names are no longer treated as interchangeable with module/provider fields; this prevents false exact-value assumptions across integrations.
8. **Per-index compilation and priority:** model DSL, active behavior signatures, and matrix rules are compiled against each target index's own mapping; matrix priority now affects scheduler order instead of being descriptive metadata only.

## What query-quality records mean

ROMULUS validates that a proposed DSL clause uses allowed syntax, mapped fields, searchable fields, compatible operators, and the required time bound. Mapping-invalid native DSL falls back to the model's deterministic selectors when possible. It records accepted/rejected model search plans and executed search outcomes, including returned counts and failures. Those checks measure **query admissibility and operational results**; they do not establish that a query was semantically relevant or exhaustive. I have not replayed a labeled historical query set here, so there is no measured syntax-accuracy or relevance percentage yet.

## Research references

- [Elastic bool query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-bool-query) — `filter`, `must`, `should`, and `minimum_should_match` behavior.
- [Elastic term query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-term-query) and [match query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-match-query) — exact values versus analyzed text.
- [Elastic wildcard query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-wildcard-query) and [keyword mappings](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/keyword) — substring query behavior, mapping types, and cost considerations.
- [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event) — `event.original` is not indexed by default.
- [Elastic Windows integration mappings](https://www.elastic.co/docs/reference/integrations/windows) — Windows event and PowerShell field types.
- [Elastic Auditd logs](https://www.elastic.co/docs/reference/integrations/auditd), [Auditd Manager](https://www.elastic.co/docs/reference/integrations/auditd_manager), and [System integration](https://www.elastic.co/docs/reference/integrations/system) — Linux audit/authentication field coverage.
- [Elastic PowerShell detection example](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_posh_compressed.toml) — script-block sequencing and event content.
- [Elastic Linux auditd sequence example](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_suspicious_suid_binary_execution_auditd_sequence.toml) — cross-event process correlation beyond a single bool query.
