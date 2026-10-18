# Milestone acceptance checklists

Each item maps to the spec (`ENGINEERING_MASTER_PROMPT.md`). Check an item only with an **evidence** link: a test name, command output in a results file, a commit, or a demo note. The lead owns this file. Subagents propose evidence; the lead verifies it and ticks the box.

Status words: `implemented` · `locally tested` · `integration tested` · `lab evaluated` · `holdout evaluated` · `production validated`.

## M1: thin end-to-end slice (spec §17)

- [ ] Package skeleton, `uv` lockfile, `.env.example`, config loader with secret redaction (§4)
- [ ] SQLite plus Alembic migrations for M1 tables; hunt manifest immutable after start (§8, §1 reproducibility)
- [ ] `doctor`: ES, Arkime, Ollama, TShark, disk, DB, least-privilege check (refuses superuser) (§4, §14)
- [ ] ES adapter: read-only HTTP allowlist with a write-trap test; PIT plus `search_after`; aggregations with completeness flags (§6)
- [ ] Source profile plus field contract generated from the live lab mapping (§6)
- [ ] Typed normalizers: `linux.audit` (EXECVE argv), `apache.access`, `systemd.journal` (auth subset), `suricata.eve.{alert,flow,dns,http}` (§8)
- [ ] ~5 host and ~3 network playbooks with fixtures, including adversarial negatives (§7, §9)
- [ ] Finding admission plus lanes; standalone findings published immediately (§10)
- [ ] Agent loop: case queue, brief builder, schema-validated decision, 3–4 pivot tools, rejection logging, context-budget and truncation check (§11)
- [ ] Web UI: login, hunt list, live hunt view (SSE), finding detail with highlighted raw evidence (§5)
- [ ] Report manifest plus JSON plus technical Markdown renderer (§13)
- [ ] Deployed to the VM; a hunt over SL700 e_a produces cited findings and at least one agent pivot chain (demo)
- [ ] `reviewer` milestone review: no Blocking findings open
- [ ] Owner demo recorded in STATUS.md

## M2: evaluation harness and model bakeoff

- [ ] Gold opportunity inventory for e_a (eval-custodian; on the VM, not the repo)
- [ ] Scoring scripts plus `docs/eval/PROTOCOL.md`
- [ ] Simple "standard searches" baseline runner
- [ ] Model bakeoff task set, runner, and results; ADR selecting triage/synthesis models and `num_ctx`
- [ ] First lab evaluation results file with miss funnel

## M3: full sources and coverage truth

- [ ] Arkime adapter plus field contract from `/api/fields`; aggregate endpoints; count semantics
- [ ] TShark adapter: path allowlist, AST filters, one-pass extraction cache
- [ ] Per-rule × source × partition coverage ledger
- [ ] Fault-injection suite: no false complete negatives (§9, gate 3)
- [ ] Entity profiles plus full pivot catalog
- [ ] Crash/resume tests at task transitions

## M4: detection depth

- [ ] Expanded playbook pack plus Sigma import (with upstream commit provenance)
- [ ] Zeek normalizers plus playbooks
- [ ] OpenSearch/Malcolm source contract (fixtures; live pending until the Malcolm VM exists)
- [ ] ICS playbooks plus baselines on public ICS PCAP fixtures; CCTV/RTSP Loss-of-View playbook on SL700
- [ ] Discovery lane with separate budget and measured incremental value
- [ ] Triage workflow, suppressions with expiry, `lead`/`analyst` roles

## M5: synthesis and reports

- [ ] Attack-path assembly (observed vs. inferred edges)
- [ ] Narrative with per-sentence citation checking
- [ ] Recommendations linked to findings and ATT&CK mitigations
- [ ] Executive DOCX from template; read-back consistency test; LibreOffice page renders
- [ ] Technical Markdown complete; IOC export; report revisions
- [ ] Owner readability review of both reports

## M6: hardening and holdout

- [ ] Web authentication, TLS, CSP, CSRF; XSS and formula-injection tests (§16 #21)
- [ ] Security review (`/security-review` plus reviewer security brief)
- [ ] Backup/restore drill; offline wheelhouse install
- [ ] Holdout pre-registered and run once; results published
- [ ] Release gate review (§15 gates 1–9)
