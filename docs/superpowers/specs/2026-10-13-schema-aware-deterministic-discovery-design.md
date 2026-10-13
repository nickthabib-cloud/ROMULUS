# Schema-aware deterministic discovery design

## Problem

The bounded live hunt proved that candidate diversity alone is insufficient. Seventeen of twenty-four deterministic host searches failed at Elasticsearch, no host events reached analysis, and conspicuous DNS-transfer records remained raw evidence. ROMULUS did recover the attacker scan as a candidate, so the responsible boundary is now retrieval and deterministic promotion rather than finding admission.

The current mapping inventory records names but not field types and includes object containers as if they were searchable leaves. Catalog compilation then applies text predicates to every semantic alias without considering whether a field is an object, numeric, IP, keyword, wildcard, or analyzed text. More signatures would reproduce the same failures.

DNS aggregation examines only the first label of a query name. Encoded transfers whose first label is a short sequence marker therefore evade the high-entropy signal even when later labels are long and entropic. A single unusual query is also too weak to distinguish transfer/tunneling from ordinary CDN or tracking traffic.

## Design

### Queryable field capabilities

Flatten Elasticsearch mappings into queryable leaf fields only. Preserve every observed concrete type for each field, including safe multi-fields, and never bind `object` or `nested` containers to semantic roles.

Persist global and source-family field capability maps in hunt state. Existing field-name lists remain for compatibility, but they are derived from queryable capabilities rather than container names.

Behavior and trusted-indicator compilation receives the capability map. It emits a clause only when the operator is compatible with every concrete mapping type observed for that bound field:

- `exists` accepts any queryable leaf;
- exact equality and trusted exact indicators use `term`/`terms` on exact-value types and `match_phrase` on analyzed text;
- containment uses bounded phrase matching only on textual types;
- path-prefix matching uses `prefix` only on exact string types and phrase matching on analyzed text;
- regex remains post-collection only.

If a required predicate has no compatible field, the analytic is recorded as unsupported instead of producing a source error. Compiler output must stay within the existing query validator and time boundary.

### DNS sequence aggregation

Evaluate every bounded DNS label, not only the first. Retain the strongest label metrics and group queries by source plus a conservative terminal-domain suffix.

Add a `dns_encoded_label_burst` aggregate when at least five timestamped queries within ten minutes share a source/suffix and contain distinct long high-entropy labels. Cite up to five source evidence records and record observation/unique-label counts. This is an investigative lead, not proof of exfiltration.

Keep the existing single-record `dns_high_entropy` lead at low priority, but make it use the strongest label. The burst gets a separate catalog analytic in the same DNS/C2 corroboration family with higher specificity and explicit benign alternatives such as CDNs, security products, tracking, and authorized tunnels.

Candidate promotion is not sufficient by itself. Candidate-owned DNS question, source, protocol, and byte fields are projected through the existing bounded case-file allowlist so the reasoning model can inspect the cited behavior. Raw unowned telemetry remains outside model context, and the burst cannot publish a finding without the normal independent-corroboration and admission checks.

### Boundaries

- No evaluated dataset IP, domain, filename, timestamp, tool, account, or attack sequence enters runtime code, catalogs, prompts, or tests.
- Score or DNS association does not publish a finding or causal path.
- Search failures remain visible; no retry broadens to an unscoped query.
- This slice does not change reasoning cadence, model freedom, finding admission, or retention.

## Proof

Synthetic mapping tests reproduce object-container aliases, mixed field types, multi-fields, and incompatible predicates. They assert that all registered deterministic host seed queries validate and that unsupported predicates fail closed.

Synthetic DNS tests use unrelated domains and payloads. They prove strongest-label detection, a bounded repeated-label burst, no burst across sources/suffixes or outside the time window, stable citations, and no finding publication.

After review, an exact VM proof will run the complete dependency suite and a read-only live query-compatibility probe against the configured mapping. A full live hunt waits until reasoning cadence is addressed, avoiding another long run whose known scheduler bottleneck would obscure this slice.
