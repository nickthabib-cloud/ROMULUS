# ROMULUS Project Instructions

## Product priority

ROMULUS's primary goal is to discover, rank, and escalate meaningful indicators and suspicious behaviors across the available telemetry.

- Surface evidence-backed indicators as findings without requiring a coherent or complete attack path.
- Use correlation to add context, adjust confidence and priority, reduce noise, and guide useful follow-up searches.
- Navigate related activity when the evidence begins to resemble an attack path, but do not make path construction a prerequisite for indicator discovery, escalation, reasoning, reporting, or hunt completion.
- Treat attack-path reconstruction as an optional secondary analysis performed after the indicator findings. Label it as a hypothesis unless every relationship is directly supported.
- Judge hunt quality first by indicator recall, specificity, prioritization, evidence quality, noise control, telemetry coverage, and useful escalation. Path coherence is a secondary measure.
- Distinguish direct execution or behavior from a tool name that merely appears in arguments, search expressions, documentation, paths, package metadata, or other text.

These priorities apply to implementation, audits, hunt objectives, report design, and explanations to the operator.
