# Vendored MITRE ATT&CK data

| Item | Value |
|---|---|
| File | `enterprise-attack-20.0.json.gz` (gzip of `enterprise-attack-20.0.json`) |
| Source | https://github.com/mitre-attack/attack-stix-data, `enterprise-attack/enterprise-attack-20.0.json` |
| ATT&CK version | Enterprise 20.0 (x-mitre-collection version 20.0) |
| Upstream git blob SHA-1 | `b39ce73c609d0f028841546e042ec16ffd7fe63f` (matched on download, 2026-10-19) |
| SHA-256 of the JSON | `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` |
| SHA-256 of the .gz | `f7ea0614878d5bcc45c84333ae62eba0cdbcefdccf89d05811e5e20cd080d04e` |
| Contents | 227 techniques, 479 sub-techniques (not revoked or deprecated) |
| License | MITRE ATT&CK license, reproduced in `LICENSE.txt` (copyright designation and license must accompany any copy) |

Read it with `gzip.open`; verify the JSON SHA-256 above before use. Replace it only with a newer pinned release and a new row here.

## ATT&CK for ICS

| Item | Value |
|---|---|
| File | `ics-attack-20.0.json.gz` (gzip of `ics-attack-20.0.json`, written with mtime 0 so the archive is byte-stable) |
| Source | https://github.com/mitre-attack/attack-stix-data, `ics-attack/ics-attack-20.0.json` |
| ATT&CK version | ICS 20.0 (x-mitre-collection "ICS ATT&CK", version 20.0), the same release as the Enterprise bundle |
| Upstream git blob SHA-1 | `e1a3a1a053d4b5c90067a73ceffc4ba6e9054b7e` (matched on download, 2026-11-05) |
| SHA-256 of the JSON | `7bffdff9853f04117a607bb5de652140a5724a3a06afc88bdc3faee37103d622` |
| SHA-256 of the .gz | `7dfad63ec7c72bd98e2d9ed0a4a88e220dab91c83f0c96e8b6b5f756daf3b4ae` |
| Contents | 104 techniques and sub-techniques (not revoked or deprecated) |
| License | MITRE ATT&CK license, reproduced in `LICENSE.txt` |

ICS technique ids are validated against this bundle as Enterprise ids are against the Enterprise bundle. Revoked ids
are never cited: in this release T0855 (Unauthorized Command Message) is revoked by T1692.001 (Command Message).
