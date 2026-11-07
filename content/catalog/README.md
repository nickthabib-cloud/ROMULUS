# Detection catalog

The authenticated /catalog pages expose registered rules, active local Sigma rules and current indicator lists. The views include ATT&CK Enterprise and ICS techniques, tools, living-off-the-land binaries, themes, and telemetry families. Empty rule mappings are coverage gaps.

rule_tags.yaml contains public names and explicit registered rule mappings. A tool mapping means that a rule covers a referenced behavior; it does not establish that the tool itself was identified. The loader rejects unknown rule IDs.

Applicability uses stored source profiles and typed field contracts. Profiles older than 30 days, incomplete inventories, or profiles without field information are unknown. A profile's fields describe source capability; individual records can still lack required evidence.

Hit counts and disposition-event counts are SQL aggregates over retained hunts. Deleted hunts are excluded. Indicator-list findings share the ioc.indicator_match identity, so the catalog does not invent per-list hit counts. CSV and Markdown exports preserve the selected rule filters and guard formula-prefixed cells.
