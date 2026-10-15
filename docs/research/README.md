# ROMULUS Intelligence Documents

This directory separates authoritative machine data, generated operator inventory, and research notes.

## Start here

- [indicator-priority-inventory.md](indicator-priority-inventory.md) lists the name, research priority, and current runtime state of every curated behavior. It is generated from the corpus and packs.
- [common-indicator-research.md](common-indicator-research.md) explains the research model, prioritization principles, sources, and implementation boundaries.
- [elasticsearch-dsl-search-matrix.md](elasticsearch-dsl-search-matrix.md) explains the field-aware Elasticsearch matrix and the query quality controls.
- [windows-event-log-threat-hunting.md](windows-event-log-threat-hunting.md) explains Windows event coverage, useful event relationships, and collection limitations.
- [2026-10-15-secondary-project-audit.md](2026-10-15-secondary-project-audit.md) records the independent repository audit, repairs, and remaining verification limits.

## Machine sources

- `common-indicator-corpus.json` is the authoritative 3,863-record research corpus.
- `scripts/behavior_pack_translations.json` contains reviewed execution semantics.
- `romulus/intelligence/attack_catalog.json` is the pinned ATT&CK authority.

Run `python scripts/build_behavior_packs.py --check`, `python scripts/build_intelligence_docs.py --check`, and `python scripts/audit_intelligence_assets.py` after intelligence changes.

## Runtime terms

- **Loaded** means the asset passed integrity checks.
- **Executable** means exact machine semantics exist.
- **Executed** means a hunt actually evaluated the rule with the required source.
- **Matched** means the declared condition matched cited evidence.
- **Partial** means missing, failed, capped, or truncated input prevents a negative conclusion.
- **Reference only** means the record can provide bounded context or records a translation gap; it cannot create a finding.
