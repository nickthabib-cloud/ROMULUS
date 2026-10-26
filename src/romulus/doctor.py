"""Read-only environment checks: sources, least privilege, model endpoint, tools, storage."""
from __future__ import annotations

import ipaddress
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from romulus.agent.provider import EGRESS_SWITCH_VALUE, agent_readiness, build_provider
from romulus.agent.provider.egress import Resolver, system_resolver
from romulus.config import Settings, redact_text
from romulus.detect.netdef import INTERNAL_SETTING, SiteNetworks
from romulus.hunt.site_networks import check_host_addresses
from romulus.site import SiteValidationError, load_site_facts
from romulus.sources.es import ElasticClient, SourceError
from romulus.sources.profile import contract_from_types, flatten_mapping
from romulus.store.db import integrity_check, make_engine, migrate, space_report


@dataclass
class Check:
    name: str
    status: str            # ok | warn | fail
    detail: str = ""
    data: dict = field(default_factory=dict)


def check_es(s: Settings) -> list[Check]:
    out: list[Check] = []
    c = ElasticClient(s)
    try:
        info = c.info()
        out.append(Check("es.reachable", "ok", f"{s.es_flavor} {c.version} cluster={info.get('cluster_name')}"))
    except SourceError as e:
        return [Check("es.reachable", "fail", str(e))]
    if s.es_url.startswith("http://"):
        out.append(Check("es.tls", "warn", "plain HTTP to Elasticsearch (lab exception)"))
    try:
        who = c.authenticate()
        roles = who.get("roles", [])
        privileged = "superuser" in roles or who.get("username") == "elastic"
        out.append(Check("es.account", "fail" if privileged and not s.allow_privileged_source_account else "ok",
                         f"user={who.get('username')} roles={roles}"))
    except SourceError as e:
        out.append(Check("es.account", "warn", f"cannot read identity: {e}"))
    try:
        concrete = []
        for pat in s.es_index_patterns:
            names = c.resolve(pat)
            concrete += names
            out.append(Check(f"es.index[{pat}]", "ok" if names else "fail", f"resolves to {names}"))
        if concrete:
            p = c.has_privileges(concrete)
            cl = p.get("cluster", {})
            idx = p.get("index", {})
            writes = sorted({f"{i}:{k}" for i, privs in idx.items() for k, v in privs.items() if v and k != "read"})
            reads = [i for i, privs in idx.items() if privs.get("read")]
            bad_cluster = sorted(k for k in ("all", "manage", "manage_security") if cl.get(k))
            status = "ok" if not writes and not bad_cluster else "fail"
            out.append(Check("es.least_privilege", status,
                             f"read on {len(reads)}/{len(concrete)} indices; write-capable={writes or 'none'}; "
                             f"cluster-admin={bad_cluster or 'none'}"))
    except SourceError as e:
        out.append(Check("es.privileges", "warn", str(e)))
    return out


def check_site_networks(s: Settings, client: ElasticClient | None = None) -> Check:
    """The internal-network definition, checked against the addresses of the site's own hosts (host.ip in host
    telemetry). Outside addresses, or no definition at all, are warnings that name the setting; never a failure."""
    try:
        definition = SiteNetworks.from_settings(s)
    except ValueError as error:
        return Check("site.internal_networks", "fail", str(error))
    notes = []
    if not definition.configured:
        notes.append(f"internal networks are not set (Site setup page or {INTERNAL_SETTING}): "
                     f"{definition.summary()}; rules whose negative depends on traffic direction report partial "
                     "coverage")
    client = client or ElasticClient(s)
    try:
        contracts = {target: contract_from_types(target, flatten_mapping(client.mapping(target)))
                     for pattern in s.es_index_patterns for target in client.resolve(pattern)}
        result = check_host_addresses(client, contracts, definition, None)
    except SourceError as e:
        notes.append(f"{definition.summary()}; host addresses could not be checked: {e}")
        return Check("site.internal_networks", "warn", "; ".join(notes))
    if not result["values_present"]:
        unchecked = "; ".join(f"{t}: {why}" for t, why in sorted(result["unchecked_targets"].items()))
        notes.append(f"{definition.summary()}; no host.ip value in host telemetry ({result['window']}), so the "
                     "definition could not be checked against the site's own hosts"
                     + (f" ({unchecked})" if unchecked else ""))
    elif not result["outside"]:
        notes.append(f"{definition.summary()}; every host.ip value in host telemetry ({result['window']}) is inside")
    if result["warning"]:
        notes.append(result["warning"])
    status = "warn" if result["warning"] or not definition.configured else "ok"
    return Check("site.internal_networks", status, "; ".join(notes), data=result)


def check_arkime(s: Settings) -> Check:
    try:
        r = httpx.get(f"{s.arkime_url.rstrip('/')}/api/sessions", params={"date": "1", "length": "1"},
                      auth=httpx.DigestAuth(s.arkime_username, s.arkime_password.get_secret_value()),
                      verify=s.arkime_verify_tls, timeout=15)
        return Check("arkime.reachable", "ok" if r.status_code == 200 else "fail", f"HTTP {r.status_code}")
    except httpx.HTTPError as e:
        return Check("arkime.reachable", "fail", redact_text(str(e), s))


def _private_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def check_ollama(s: Settings) -> list[Check]:
    if not s.ollama_url:
        return [Check("ollama.endpoint", "ok", "no model endpoint configured: model features are off")]
    out = []
    base = s.ollama_url.rstrip("/")
    host = httpx.URL(base).host
    if not _private_host(host):
        out.append(Check("ollama.endpoint", "fail", f"{host} is not a private/host-only address"))
    try:
        v = httpx.get(f"{base}/api/version", timeout=10).json().get("version")
        tags = [m["name"] for m in httpx.get(f"{base}/api/tags", timeout=10).json().get("models", [])]
        out.append(Check("ollama.reachable", "ok", f"version {v}; models={tags}"))
        for model in {s.ollama_model_triage, s.synthesis_model}:
            if model not in tags:
                out.append(Check(f"ollama.model[{model}]", "fail", "not pulled"))
                continue
            show = httpx.post(f"{base}/api/show", json={"model": model}, timeout=20).json()
            ctx = next((v for k, v in show.get("model_info", {}).items() if k.endswith(".context_length")), None)
            st = "ok" if ctx is None or s.ollama_num_ctx <= ctx else "fail"
            out.append(Check(f"ollama.model[{model}]", st, f"num_ctx={s.ollama_num_ctx} model_max={ctx}"))
    except httpx.HTTPError as e:
        out.append(Check("ollama.reachable", "fail", str(e)))
    return out


def check_agent(s: Settings, transport: httpx.BaseTransport | None = None,
                resolver: Resolver = system_resolver) -> list[Check]:
    """The AI agent's provider: configuration, egress class, reachability, model, tool calls, schema, usage."""
    try:
        readiness = agent_readiness(s, resolver)
    except Exception as exc:  # noqa: BLE001 - a readiness error is a failed check
        return [Check("agent.provider", "fail", redact_text(f"agent readiness check failed: {exc}", s))]
    if readiness.state == "not_configured":
        return [Check("agent.provider", "ok", f"{readiness.message()}; hunts run without the AI agent")]
    if readiness.state == "blocked":
        return [Check("agent.provider", "fail", readiness.message())]
    d = readiness.decision
    out = [Check("agent.provider", "ok", f"{readiness.provider} model {readiness.model} at {d.host}")]
    if d.egress == "remote":
        out.append(Check("agent.egress", "warn",
                         f"remote endpoint {d.host}, allowed only by ROMULUS_MODEL_EGRESS={EGRESS_SWITCH_VALUE}: "
                         "telemetry excerpts will be sent to it; hunt public data only"))
    else:
        out.append(Check("agent.egress", "warn" if s.model_egress else "ok",
                         f"local endpoint ({d.basis})" + ("; ROMULUS_MODEL_EGRESS is set but not needed: unset it"
                                                          if s.model_egress else "")))
    if readiness.provider == "openai_compatible" and not s.agent_context_tokens and d.egress == "local":
        out.append(Check("agent.context", "warn", "AGENT_CONTEXT_TOKENS is 0: a local server that silently cuts "
                                                  "long prompts cannot be detected; set it to the model's context window"))
    provider = build_provider(s, transport=transport, resolver=resolver, readiness=readiness)
    try:
        probes = provider.probe()
    except Exception as exc:  # noqa: BLE001 - a broken or hostile endpoint must not take the other checks down
        probes = [("agent.reachable", "fail", f"probe failed: {exc.__class__.__name__}: {exc}"[:300])]
    for name, status, detail in probes:
        out.append(Check(name, status, redact_text(detail, s)))
    return out


def check_tshark(s: Settings) -> Check:
    exe = shutil.which(s.tshark_bin)
    if not exe:
        return Check("tshark", "fail", f"{s.tshark_bin} not found")
    v = subprocess.run(
        [exe, "--version"], check=False, capture_output=True, text=True, timeout=20
    ).stdout.splitlines()[:1]
    return Check("tshark", "ok", v[0] if v else exe)


def check_paths(s: Settings, env_file: Path | None) -> list[Check]:
    out = []
    eval_root = s.eval_root.resolve() if s.eval_root else None
    for d in s.pcap_allowed_dirs:
        rd = d.resolve()
        if eval_root is not None and (eval_root in (rd, *rd.parents) or rd in eval_root.parents):
            out.append(Check("paths.eval_isolation", "fail", f"PCAP allowlist {d} overlaps ground truth"))
        out.append(Check(f"paths.pcap[{d}]", "ok" if rd.is_dir() else "fail", "exists" if rd.is_dir() else "missing"))
    if env_file and env_file.exists() and os.name == "posix":
        mode = stat.S_IMODE(env_file.stat().st_mode)
        out.append(Check("paths.env_mode", "ok" if mode & 0o077 == 0 else "fail", oct(mode)))
    s.home.mkdir(parents=True, exist_ok=True)
    free_gb = shutil.disk_usage(s.home).free / 1e9
    out.append(Check("disk.free", "ok" if free_gb > 10 else "warn", f"{free_gb:.1f} GB free at {s.home}"))
    out.append(check_state_budget(s))
    out.append(check_stage_volume(s))
    return out


# Data directories of services that may share a host with ROMULUS: a stage on their volume can fill it (Elasticsearch
# blocks writes to its indices at its flood-stage watermark). Only paths that exist are compared.
SERVICE_DATA_PATHS = {
    "Elasticsearch": ("/var/lib/elasticsearch", "/usr/share/elasticsearch/data", "/var/lib/opensearch",
                      "/usr/share/opensearch/data"),
    "Arkime": ("/opt/arkime/raw", "/data/arkime", "/opt/molochd/raw", "/data/moloch/raw"),
    "docker": ("/var/lib/docker", "/var/lib/containerd"),
}


def _elasticsearch_data_paths() -> list[str]:
    """`path.data` entries of a local Elasticsearch or OpenSearch configuration, when readable."""
    found = []
    for config in ("/etc/elasticsearch/elasticsearch.yml", "/etc/opensearch/opensearch.yml"):
        try:
            text = Path(config).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("path.data:"):
                value = line.split(":", 1)[1].strip().strip("[]\"'")
                found += [part.strip().strip("\"'") for part in value.split(",") if part.strip()]
    return found


def check_stage_volume(s: Settings, paths: dict[str, tuple[str, ...]] | None = None) -> Check:
    """Warn when the stage directory is on the same filesystem as another service's data it can detect."""
    stage = s.stage_path
    probe = stage
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        device = probe.stat().st_dev
    except OSError as exc:
        return Check("stage.volume", "warn", f"cannot read the stage directory {stage}: {exc}")
    services = dict(paths if paths is not None else SERVICE_DATA_PATHS)
    if paths is None:
        services["Elasticsearch"] = (*services["Elasticsearch"], *_elasticsearch_data_paths())
    shared = []
    for service, candidates in services.items():
        for candidate in candidates:
            try:
                if Path(candidate).exists() and Path(candidate).stat().st_dev == device:
                    shared.append(f"{service} ({candidate})")
                    break
            except OSError:
                continue
    if shared:
        return Check("stage.volume", "warn", f"the stage directory {stage} is on the same filesystem as "
                                             f"{', '.join(shared)}: point ROMULUS_STAGE_DIR at another volume, so a "
                                             f"hunt's stage can never fill theirs")
    return Check("stage.volume", "ok", f"{stage} shares no filesystem with a detected service's data")


def check_state_budget(s: Settings) -> Check:
    """The sweep's detector-state budget on the stage volume: fail when its free space is already at the reserve
    (rules that keep state would evaluate nothing), warn when the hunt's disk total is under 1 GiB."""
    from romulus.hunt.sweep import state_budget
    budget = state_budget(s, s.stage_path)
    free = budget.free()
    detail = (f"disk total {budget.disk_total / 2**30:.1f} GiB, reserve {budget.reserve / 2**30:.1f} GiB, "
              f"memory {budget.memory_total / 2**20:.0f} MiB; stage volume "
              + (f"{free / 2**30:.1f} GiB free" if free is not None else "free space unreadable"))
    if budget.preflight():
        return Check("state.budget", "fail", detail + "; free space is below the reserve: rules that keep state "
                                                      "would evaluate no records")
    return Check("state.budget", "warn" if budget.disk_total < 2**30 else "ok", detail)


def check_db(s: Settings) -> Check:
    e = make_engine(s.db_path)
    migrate(e)
    res = integrity_check(e)
    return Check("db.integrity", "ok" if res == "ok" else "fail", f"{s.db_path}: {res}")


def check_db_space(s: Settings) -> Check:
    """Warn when most of the database file is reclaimable (free pages or an oversized write-ahead log)."""
    rep = space_report(make_engine(s.db_path))
    reclaim = rep["free_bytes"] + rep["wal_bytes"]
    total = rep["file_bytes"] + rep["wal_bytes"]
    detail = (f"file {rep['file_bytes'] / 1e6:.0f} MB, write-ahead log {rep['wal_bytes'] / 1e6:.0f} MB, "
              f"reclaimable {reclaim / 1e6:.0f} MB")
    big = reclaim > 200e6 and total and reclaim / total > 0.5
    return Check("db.space", "warn" if big else "ok",
                 detail + ("; run `romulus db compact` when no hunt is running" if big else ""))


def check_site(s: Settings) -> Check:
    try:
        facts = load_site_facts(s.home)
    except SiteValidationError as exc:
        return Check("site.collection", "fail", str(exc))
    if not facts.present:
        return Check(
            "site.collection",
            "warn",
            "site/collection.yaml is absent; optional, but nothing is attested",
        )
    return Check(
        "site.collection",
        "ok",
        f"valid; {len(facts.groups)} collection group(s)",
        {"digest": facts.digest, "groups": len(facts.groups)},
    )


def run_all(s: Settings, env_file: Path | None = None) -> list[Check]:
    checks = check_es(s)
    checks.append(check_site_networks(s))
    checks.append(check_arkime(s))
    checks += check_ollama(s)
    checks += check_agent(s)
    checks.append(check_tshark(s))
    checks += check_paths(s, env_file)
    checks.append(check_site(s))
    checks.append(check_db(s))
    checks.append(check_db_space(s))
    return checks
