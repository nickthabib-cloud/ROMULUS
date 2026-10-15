# ROMULUS Codex operating instructions

ROMULUS is a defensive threat-hunting application. Read README.md and inspect the relevant code and tests before proposing changes. The repository and executable tests—not prior chat claims—are the source of truth.

## Default operating rules
- Prefer read-only inspection first. Never claim a feature works, is dead, or is tested without file references and supporting evidence.
- Preserve defensive, read-only telemetry collection and the deterministic evidence/admission boundaries described in README.md.
- Never invent evidence, alerts, ATT&CK mappings, coverage, execution results, or test outcomes.
- Keep changes narrow. Record assumptions, affected components, regression risks, and verification commands.
- Do not remove apparently unused code until references, entry points, dynamic imports, optional adapters, and tests have been checked.
- Never commit secrets, credentials, private telemetry, or generated sensitive reports.
- Never merge to main, deploy, modify production systems, or delete substantial code without explicit user approval.
- For implementation, require a scoped task, acceptance criteria, and tests; report tests not run separately from tests passed.
- Treat reviewer/tester roles as independent checks, not as proof merely because another model approved a change.

## Roles
- Lead: read `agents/lead.md`.
- Developer: read `agents/developer.md`.
- Auditor: read `agents/auditor.md`.
- Tester: read `agents/tester.md`.

These role files are reusable instructions, not automatic Codex subagent registrations. Use dedicated sessions with the corresponding role instructions unless actual subagent orchestration has been configured and verified.
