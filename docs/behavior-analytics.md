# Maintaining ROMULUS behavior analytics

ROMULUS keeps its starting hunt knowledge in two offline, version-controlled files:

- `romulus/intelligence/behavior_catalog.json` contains behavioral seed analytics.
- `romulus/intelligence/local_indicators.json` contains operator-supplied trusted exact indicators.

The format reference is `romulus/intelligence/behavior_catalog.schema.json`. Loading either catalog is fail-closed: malformed JSON, duplicate IDs, unknown roles or operators, invalid confidence values, and invalid dates stop a hunt before telemetry searches begin.

## Behavior catalog entries

Each behavior has a stable ID and version, supported platforms and categories, required semantic roles, a deterministic predicate, ATT&CK mappings, benign explanations, expected corroboration, follow-up guidance, provenance, a review date, and a reviewed `classification_policy`.

Use semantic roles such as `process.command_line`, `process.executable`, `file.path`, `source.ip`, or `dns.question`. Do not add dataset-specific Elasticsearch field names to predicates. ROMULUS binds semantic roles to fields discovered in the current dataset and records entries it cannot apply.

Allowed predicate operators are `contains_any`, `equals_any`, `ends_with_any`, `path_prefix_any`, `regex`, `exists`, and `lookalike_process`.

A weak anomaly should have a low `base_priority`, high `expected_noise`, realistic benign explanations, explicit corroboration requirements, and `classification_policy.default_classification` set to `anomalous`. A high-specificity composite such as a reverse-shell construction can default to `suspicious` and permit a single owned record when the required context roles make the behavior adversary-relevant. Catalog behaviors never default to `malicious`.

The policy fields are:

- `default_classification`: `anomalous` or `suspicious`;
- `single_record_reportable`: whether one distinct owned evidence record is sufficient;
- `minimum_owned_evidence`: the exact distinct-record minimum;
- `required_context_roles`: semantic roles that must be present in the deterministic predicate;
- `upgrade_rule`: `none` or `independent_typed_entity_within_30m`;
- `downgrade_rule`: currently `explicit_benign_evidence_only`;
- `policy_version` and `policy_reason`: review provenance for the classification decision.

These fields define evidentiary meaning. `base_priority`, score, and confidence remain scheduling and strength signals and cannot replace the policy.

To add an analytic:

1. Copy a nearby entry in `romulus/intelligence/behavior_catalog.json`.
2. Assign a new stable ID such as `BH-WIN-019`; never reuse an old ID for different logic.
3. Increment the entry version when changing its matching behavior.
4. Add primary source provenance and a current `review_date`.
5. State expected benign cases and bounded follow-up searches.
6. Add a complete classification policy and verify every required context role is present in the predicate.
7. Add positive and negative fixtures to `tests/test_behavior_catalog.py`, including singular-reportability and fail-closed cases.
8. Run the validation and test commands below.

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
  "classification": "malicious",
  "created_at": "2026-10-12T00:00:00Z",
  "expires_at": "2027-01-12T00:00:00Z"
}
```

Supported types are `sha256`, `sha1`, `md5`, `domain`, `ip`, `path`, `process`, and `certificate`. Matching is exact after type-specific normalization. Expired indicators are ignored. Missing `classification` defaults to `suspicious`. `malicious` is accepted only for a current exact indicator with complete provenance and confidence of at least 90; otherwise loading or admission fails closed. A malicious indicator match is explicit evidence under that local rule, but it is still not permission for automatic containment or proof of a complete compromise.

## Candidate truth, status, and priority

Behavior and indicator matches enter the persisted `candidate_leads` working list.

- `classification` is the final reviewed evidentiary category: `anomalous`, `suspicious`, or `malicious`.
- `investigation_status` is independent: `new`, `investigating`, `follow_up_exhausted`, `resolved`, or `dismissed`.
- Priority and confidence control queue order and describe evidence strength; neither promotes classification.
- An authorized relationship upgrade requires separate owned records sharing a typed entity within the allowed time window. Repeated copies of one record do not corroborate themselves.
- A completed or blocked follow-up changes investigation status, not truth. Lack of corroboration does not erase a singular high-specificity suspicious observation.
- Classification changes record the old/new value, exact deterministic rule, cited evidence IDs, and timestamp.

Scores and their reasons are stored with every candidate so an analyst can see why it moved.

## Report streams and possible narrative

Non-dismissed suspicious and malicious candidates enter the primary Word and text reports even when no complete attack path can be constructed. Unresolved anomalous-only candidates from a finalized hunt enter a separate compact text queue under `reports/anomalous/`; they remain leads, not conclusions.

The optional `Hypothesis: Possible Activity Narrative` is built after factual report items are fixed. The model receives at most twelve accepted report items, 48 owned evidence facts, and stable admitted relationship IDs. Code rejects unknown or cross-item citations, repeated placement, disconnected clusters, invented IP/domain/time facts, unauthorized fields, and unsupported causal claims. Unconnected items remain listed. The admitted narrative never changes evidence, findings, classifications, or retention eligibility.

## Validation

From the repository root:

```bash
python -c "from romulus.intelligence.behavior_catalog import load_behavior_catalog, load_local_indicators; print(len(load_behavior_catalog()['analytics']), len(load_local_indicators()['indicators']))"
python -m unittest tests.test_behavior_catalog -v
```

A successful first command prints the number of behavior analytics followed by the number of local indicators. Commit catalog edits with their tests so changes remain reviewable and reversible.
