# Maintaining ROMULUS behavior analytics

ROMULUS keeps its starting hunt knowledge in two offline, version-controlled files:

- `romulus/intelligence/behavior_catalog.json` contains behavioral seed analytics.
- `romulus/intelligence/local_indicators.json` contains operator-supplied trusted exact indicators.

The format reference is `romulus/intelligence/behavior_catalog.schema.json`. Loading either catalog is fail-closed: malformed JSON, duplicate IDs, unknown roles or operators, invalid confidence values, and invalid dates stop a hunt before telemetry searches begin.

## Behavior catalog entries

Each behavior has a stable ID and version, supported platforms and categories, required semantic roles, a deterministic predicate, ATT&CK mappings, benign explanations, expected corroboration, follow-up guidance, provenance, and a review date.

Use semantic roles such as `process.command_line`, `process.executable`, `file.path`, `source.ip`, or `dns.question`. Do not add dataset-specific Elasticsearch field names to predicates. ROMULUS binds semantic roles to fields discovered in the current dataset and records entries it cannot apply.

Allowed predicate operators are `contains_any`, `equals_any`, `ends_with_any`, `path_prefix_any`, `regex`, `exists`, and `lookalike_process`.

A weak anomaly should have a low `base_priority`, high `expected_noise`, realistic benign explanations, and explicit corroboration requirements. Execution from a temporary directory is the reference example. A specific composite such as a reverse shell can start higher, but it remains an investigative lead until supported by evidence.

To add an analytic:

1. Copy a nearby entry in `romulus/intelligence/behavior_catalog.json`.
2. Assign a new stable ID such as `BH-WIN-019`; never reuse an old ID for different logic.
3. Increment the entry version when changing its matching behavior.
4. Add primary source provenance and a current `review_date`.
5. State expected benign cases and bounded follow-up searches.
6. Add positive and negative fixtures to `tests/test_behavior_catalog.py`.
7. Run the validation and test commands below.

## Trusted exact indicators

The repository intentionally ships with an empty `romulus/intelligence/local_indicators.json`. Add only indicators whose provenance you trust.

Each indicator requires:

```json
{
  "id": "IOC-EXAMPLE-001",
  "type": "domain",
  "value": "example.invalid",
  "source": "Customer incident response case 123",
  "confidence": 95,
  "created_at": "2026-10-12T00:00:00Z",
  "expires_at": "2027-01-12T00:00:00Z"
}
```

Supported types are `sha256`, `sha1`, `md5`, `domain`, `ip`, `path`, `process`, and `certificate`. Matching is exact after type-specific normalization. Expired indicators are ignored. A trusted match is reported as “trusted indicator observed”; it is not automatically described as confirmed compromise.

## Candidate priority

Behavior and indicator matches enter the persisted `candidate_leads` working list.

- Trusted current exact indicators enter the critical tier.
- Specific behavior with an independent behavior on the same asset can become corroborated and customer-visible.
- Temporary paths, process rarity, lookalike names, and other weak anomalies begin low.
- Low and unresolved entries remain in the technical candidate appendix.
- Only trusted or corroborated high-priority entries appear in the customer-facing prioritized-lead section.

Scores and their reasons are stored with every candidate so an analyst can see why it moved.

## Validation

From the repository root:

```bash
python -c "from romulus.intelligence.behavior_catalog import load_behavior_catalog, load_local_indicators; print(len(load_behavior_catalog()['analytics']), len(load_local_indicators()['indicators']))"
python -m unittest tests.test_behavior_catalog -v
```

A successful first command prints the number of behavior analytics followed by the number of local indicators. Commit catalog edits with their tests so changes remain reviewable and reversible.
