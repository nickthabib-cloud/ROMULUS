# Security

## Intended use

ROMULUS is a read-only defensive threat-hunting evaluation project. Use it only with explicit authorization for the telemetry, hosts, networks, accounts, and packet captures in scope.

## Trust boundaries

- Elasticsearch and Arkime accounts should have only the read privileges required by their adapters.
- PCAP access is restricted to explicitly configured files beneath allowlisted directories.
- The selected model provider receives bounded mission context, field catalogs, deterministic analytics, and selected evidence excerpts. Ollama is local by default. Selecting OpenAI additionally requires `ALLOW_CLOUD_LLM=true` because those bounded inputs leave the VM for the configured API. Telemetry is treated as untrusted data.
- The model may propose structured selectors and source-native read-only query candidates. Deterministic code validates every candidate against a bounded operator grammar and discovered field catalog, adds the enforced mission time range, and falls back to compiled selectors when validation fails. Model output is never executed as shell code.
- ROMULUS does not perform active network scans, endpoint changes, containment, or remediation.

## Sensitive material

Do not commit or upload:

- `.env` files or credentials
- SQLite databases, WAL, or shared-memory files
- audit logs, findings streams, or generated reports
- PCAP/PCAPNG files
- private keys or certificates
- telemetry exports containing partner or mission data

The repository ignore rules cover these common artifacts. Review staged files before every push because ignore rules cannot remove a secret that was already committed.

OpenAI requests set `store: false`, but that is not a substitute for organizational authorization, data classification review, account policy, or provider-side retention controls. Use synthetic or otherwise approved data for capability testing. ROMULUS never writes the API key to its provider audit metadata.

## Findings and limitations

ROMULUS findings are investigative leads. They require analyst review, source validation, and consideration of benign explanations. A finding does not prove compromise, and the absence of a finding does not establish that an environment is secure.

## Reporting a vulnerability

Keep security reports private. Provide the affected version, relevant component, reproduction conditions using synthetic data where possible, and the expected security impact to the repository owner through a private GitHub security advisory or another agreed private channel.
