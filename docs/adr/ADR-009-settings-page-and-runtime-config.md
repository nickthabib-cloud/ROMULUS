# ADR-009: A lead-only settings page writes a managed config file; secrets are write-only; TLS first

**Status:** Deferred 2026-10-20 (owner: "hold off on the credentials page and do that later"). The shape below is the recommendation for when it is picked up. Until then, all configuration, including agent provider keys (ADR-007), stays in `.env`. Not implemented.

## Context

All configuration lives in `$ROMULUS_HOME/.env` (mode 0600, checked by doctor) and is loaded by `romulus.config.load_settings`. Changing a source password, an index pattern or a model key means SSH, an editor and a restart. The spec already calls for a Settings / doctor page (§5) but only for health and version information.

The lab UI is served on `192.168.36.128:8443` over **plain HTTP** under the lab exception (`romulus web` prints the warning). A credentials form on that page would send passwords in cleartext across the network.

## Decision

1. **Settings page, lead role only.** It has three sections, each with its doctor result inline:
   - sources: Elasticsearch/OpenSearch, Arkime, PCAP directories;
   - model providers (ADR-007);
   - hunt defaults: index patterns, budgets, `num_ctx`, narrative mode.
2. **A managed file, separate from bootstrap.** The UI writes `$ROMULUS_HOME/config/settings.env` with the existing `KEY=VALUE` parser format. The write is atomic: temp file, fsync, rename. The file is mode 0600 and owned by the service user. The precedence order is:
   - process environment;
   - `settings.env`;
   - `.env`;
   - defaults.

   Each field shows where its value comes from. A value set in the process environment is read-only on the page, with an explanation.
3. **Bootstrap keys never come from the UI.** These keys are ignored if they appear in `settings.env`:
   - `ROMULUS_HOME`;
   - `ROMULUS_WEB_BIND` and `ROMULUS_WEB_TLS_*`;
   - `ROMULUS_SECRET_KEY`;
   - `ROMULUS_MODEL_EGRESS` (ADR-007);
   - `ROMULUS_ALLOW_PRIVILEGED_SOURCE_ACCOUNT`.

   A browser session can't lock the service out, re-bind it or enable egress.
4. **Secrets are write-only.**
   - They are never rendered back into HTML, not even masked or as a length. The page shows `set · changed 2026-10-20 14:02 by <username>`.
   - An empty field keeps the current value. Clearing a secret needs an explicit checkbox.
   - Secrets never go into SQLite (the DB is copied, compacted and read by the eval tooling), logs or the audit trail. The audit records the key name, actor, time, and old and new values for non-secrets only.
5. **TLS before secrets.** Secret fields render only over TLS or from loopback. On plain HTTP the section says why and how to fix it. `romulus web tls-init` generates a self-signed certificate under `$ROMULUS_HOME/tls/`. Web TLS therefore moves from M7 hardening to this work.
6. **Step-up and the usual web controls.** Saving needs the lead's password to be re-entered, plus CSRF, login rate limiting and the strict CSP.
7. **Test before save.** Each section's "Test" button runs that doctor check against the submitted values. Errors pass through `redact_text`. The read-only privilege check applies, and a superuser or write-capable source account is refused as today.
8. **Effect on hunts.** A running hunt keeps the configuration it started with. New hunts load the new revision. The hunt manifest's config digest covers non-secret values and a revision counter per secret. It never includes a hash of a secret, which could be guessed offline.

## Rejected alternatives

- **Secrets in SQLite, encrypted with a key kept on the same disk.** Anyone who can read the DB can read the key. The encryption adds key management without protecting against the threat that matters, and it puts secrets into every DB copy.
- **Rewriting `.env` from the web.** It mixes bootstrap and runtime values, loses comments, and lets one bad save break the secret key or bind address and lock the operator out.
- **OS keyring.** A headless server or air-gapped kit usually has no keyring daemon.
- **External secrets manager (Vault and similar).** It can be added later behind the same loader if a mission kit provides one; not now.

## Consequences

- `load_settings` gains the managed-file layer and a per-key source report. Doctor checks the file's mode and owner.
- New web routes: `GET/POST /settings` and `POST /settings/test/{section}`, all lead-only and CSRF-protected, plus tests for write-only rendering, precedence, bootstrap-key refusal, atomic write and redaction.
- `.env.example` keeps documenting every key. The operator guide explains which keys belong to bootstrap and which to the UI.

## Revisit if

A mission kit requires an external secrets manager or hardware-backed key storage, or multiple ROMULUS instances need to share one configuration.
