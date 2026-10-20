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

from romulus.config import Settings, redact_text
from romulus.sources.es import ElasticClient, SourceError
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
        return [Check("ollama.endpoint", "ok", "no model endpoint configured: model features are off (ADR-006)")]
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


def check_tshark(s: Settings) -> Check:
    exe = shutil.which(s.tshark_bin)
    if not exe:
        return Check("tshark", "fail", f"{s.tshark_bin} not found")
    v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20).stdout.splitlines()[:1]
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
    return out


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


def run_all(s: Settings, env_file: Path | None = None) -> list[Check]:
    checks = check_es(s)
    checks.append(check_arkime(s))
    checks += check_ollama(s)
    checks.append(check_tshark(s))
    checks += check_paths(s, env_file)
    checks.append(check_db(s))
    checks.append(check_db_space(s))
    return checks
