# Detection catalog

The authenticated /catalog pages expose registered rules, active local Sigma rules and current indicator lists. The views include ATT&CK Enterprise and ICS techniques, tools, living-off-the-land binaries, themes, and telemetry families. Empty rule mappings are coverage gaps.

rule_tags.yaml contains public names and explicit registered rule mappings. A tool mapping means that a rule covers a referenced behavior; it does not establish that the tool itself was identified. The loader rejects unknown rule IDs.

Applicability uses stored source profiles and typed field contracts. Profiles older than 30 days, incomplete inventories, or profiles without field information are unknown. A profile's fields describe source capability; individual records can still lack required evidence.

Accepted telemetry families are alternatives; only the supplied family's field requirements apply. Explicit OS, dataset, native event-class and Sigma scope must also be supported. Missing native scope or absence-capability evidence is unknown. Sigma capability follows its boolean conditions and field aliases within each native event class.

Active Sigma metadata and predicates are checked against a 32 MiB request memory budget before decoding. Exceeding that budget makes the catalog explicitly unavailable instead of silently omitting rules. Profile reads have an 8 MiB budget and a 1,000-source limit; unavailable profiles are labelled unknown. Historical candidate statistics use rule-oriented indexes and latest-row seeks; recent hunt and source-profile selection use indexed lookups.

Hit counts and disposition-event counts are SQL aggregates over retained hunts. Deleted hunts are excluded. Indicator-list findings share the ioc.indicator_match identity, so the catalog does not invent per-list hit counts. CSV and Markdown exports preserve the selected rule filters and guard formula-prefixed cells.

Detection requests at /catalog/requests are shared intake items. Active analysts can create requests and edit their own behavior text while the status is requested. Active leads can change status, linking an active request to a registered or active Sigma rule, or declining it with a reason. Every status change has an append-only history. Requests store finding and cited-event references; deleted source findings remain identified as unavailable. Requests never change a hunt or rule. Filtered CSV and YAML exports support local intake into a research register.
