# Validation record

This file records engineering validation performed against the development deployment. It is evidence of observed behavior, not an operational authorization or a claim that the environment is clean.

## 2026-10-11 — ROMULUS 0.4.0 live hunt and 0.4.1 remediation

### Readiness

`doctor` confirmed the configured Ollama model, structured reasoning response, two allowlisted Elasticsearch indexes, Arkime session API, TShark 4.2.2, three allowlisted PCAP files, writable runtime directories, and the pinned Enterprise ATT&CK v19.2 catalog.

### Controlled hunt

- Investigation: `HUNT-E5ED6B713B`
- Mission: broad malicious-actor discovery over the available historical host and network data, with an explicit 2024-11-13 window
- Limit: 600 seconds
- Result: partial / evidence-supported lead
- Calls: 36 of 160
- Analyst reasoning rounds: 4 of 10
- High-priority hypotheses tested: 8 of 9
- Initial retained context: 1,000 host events, 9,751 Arkime sessions, and 1,500 packet records
- TShark matched packets represented by the retained records: 1,035,828
- Finding: one moderate-confidence suspected credential-access lead with cited evidence and benign alternatives
- Termination: runtime resource limit after 617,286 ms

The run did not crash. It generated both Word and text reports and preserved the audit trail. The finding is an investigative lead rather than confirmation of compromise.

### Issues observed

- Some model proposals used schema or field names as literal terms.
- One TShark expression exceeded the adapter limit after the mandatory packet-time expression was appended.
- A deterministic fallback attempted an empty host text query for an unmapped hypothesis.
- Evidence anchors accumulated IP, hostname, and term constraints that could overconstrain a pivot.
- Repeated full-state LangGraph snapshots expanded the SQLite database to 14,622,371,840 bytes.

### 0.4.1 remediation

- Reject schema/field names as terms and reinforce the structured-search prompt.
- Reserve filter length for the packet-time expression and bound TShark text fields.
- Skip hypothesis fallback searches when no mapped selector exists.
- Use one anchor entity family and a ±15-minute evidence window.
- Store all unique evidence once while bounding graph analysis context per source and baseline/pivot phase.
- Move checkpoints to a separate database and retain only the newest resumable checkpoint.
- Rebuild the legacy store only after table-count and integrity verification.

The production-like database was compacted to 286,113,792 bytes while preserving 12,251 unique evidence records, the finding, investigation state, reports, and audit logs. The compactor reclaimed 14,336,258,048 bytes.

### Post-fix checks

- Python compilation and imports succeeded on the Ubuntu deployment.
- Broad ATT&CK seed selection covered common behaviors across the intrusion lifecycle.
- Focused lateral-movement selection emphasized remote services, SMB, RDP, credential use, and adjacent behavior.
- Field-name terms were rejected.
- The representative TShark expression compiled to 164 characters before the time bound.
- Anchor expansion chose IPs without adding a conflicting hostname family.
- A disposable offline graph run completed with a 45,056-byte operational database, a 32,768-byte checkpoint database, one retained checkpoint, and no checkpoint tables in the operational database.
- `doctor` was fully green after deploying 0.4.1.

### Next validation

Run a fresh controlled live hunt to measure whether the corrected query compiler produces fewer rejected or zero-result pivots and whether checkpoint storage stays bounded under several live analyst rounds. Extend runtime only if the audit shows productive hypothesis expansion near the configured ceiling.
