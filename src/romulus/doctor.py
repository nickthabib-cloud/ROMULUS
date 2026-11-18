"""Read-only environment checks: sources, least privilege, model endpoint, tools, storage."""
from __future__ import annotations

import ipaddress
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from sqlalchemy import exc as sa_exc

from romulus.agent.provider import EGRESS_SWITCH_VALUE, AgentNotReady, agent_readiness, build_provider
from romulus.agent.provider.egress import Resolver, system_resolver
from romulus.agent.provider.openai_responses import LONG_REASONING_EFFORTS, LONG_REASONING_TIMEOUT
from romulus.config import (
    FULL_ACCESS_ROLE,
    MIN_SECRET_LENGTH,
    Settings,
    redact_text,
    secret_settings,
    short_secrets,
    triage_settings,
)
from romulus.detect.netdef import INTERNAL_SETTING, SiteNetworks
from romulus.hunt.site_networks import check_host_addresses
from romulus.site import SiteValidationError, load_site_facts
from romulus.sources.es import (
    ELASTICSEARCH_MIN,
    ES_CLUSTER_WRITE_PRIVILEGES,
    OPENSEARCH_SHARD_DOC,
    TIE_GROUP_WINDOW,
    Backend,
    ElasticClient,
    SourceError,
)
from romulus.sources.network_coverage import check_network_addresses
from romulus.sources.packets import PacketError, arkime_client, check_arkime_endpoint
from romulus.sources.profile import (
    apply_zeek_declaration,
    build_profile,
    contract_from_types,
    flatten_mapping,
)
from romulus.store.db import (
    IntegrityCheckTimeout,
    integrity_check,
    make_read_only_engine,
    schema_heads,
    space_report,
)


@dataclass
class Check:
    name: str
    status: str            # ok | warn | fail
    detail: str = ""
    data: dict = field(default_factory=dict)


READ_ONLY_UNPROVEN = "read-only cannot be verified on this backend; ROMULUS's request allowlist is the write guard"

# Every client a check uses has explicit connect and read timeouts, and every check runs under a deadline of its own
# (run_all), so a service or a lock that never answers costs one check, never the run.
ES_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
ARKIME_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
OLLAMA_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
OLLAMA_SHOW_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
TSHARK_SECONDS = 20
# The model probes are a few tiny calls (each capped at a few hundred output tokens): each is cut at this many seconds
# even when AGENT_TIMEOUT_SECONDS (which a hunt's long reasoning calls may need) is longer. It leaves room for a local
# server that loads the model on its first call.
MODEL_PROBE_CALL_SECONDS = 120
# The store checks open the file read-only and wait at most this long for another process's lock, per statement.
DB_BUSY_TIMEOUT_MS = 5_000

# Per-check deadlines, in seconds (run_all). A check that overruns is reported as timed out and the run goes on.
# - A source or tool every hunt needs (Elasticsearch/OpenSearch, Arkime, TShark) or a configured model endpoint (the
#   agent, triage, Ollama) fails on a timeout: a hunt started now would stall or fail on the same service, and these
#   checks already fail when their service does not answer.
# - The store, the inventories and the local checks warn: a timeout there means "not verified", not "broken". The
#   integrity check reads the whole store, so its time grows with the store, and a large store is not a defect.
CHECK_SECONDS = 120
INVENTORY_SECONDS = 300
# the models endpoint and two probe calls, each within MODEL_PROBE_CALL_SECONDS
MODEL_SECONDS = 400
LOCAL_SECONDS = 60
DB_INTEGRITY_SECONDS = 300
# the store's integrity check stops itself at its deadline; its step's deadline is this much later, as a backstop
DB_GRACE_SECONDS = 15


def check_es(s: Settings, transport: httpx.BaseTransport | None = None) -> list[Check]:
    out: list[Check] = []
    c = ElasticClient(s, transport=transport, timeout=ES_TIMEOUT)
    try:
        info, backend, _refusal = c.probe()
        out.append(Check("es.reachable", "ok", f"{backend.label()} cluster={info.get('cluster_name')}"))
    except SourceError as e:
        return [Check("es.reachable", "fail", str(e))]
    out.append(check_flavor_version(s, backend, c.refusal))
    if c.refusal is not None:
        # the client refuses every further request against this cluster
        return out
    if s.es_url.startswith("http://"):
        name = "OpenSearch" if s.es_flavor == "opensearch" else "Elasticsearch"
        out.append(Check("es.tls", "warn", f"plain HTTP to {name} (lab exception)"))
    if s.es_flavor == "opensearch":
        return out + _check_opensearch_access(s, c)
    try:
        who = c.authenticate()
        roles = who.get("roles", [])
        privileged = "superuser" in roles or who.get("username") == "elastic"
        out.append(Check("es.account", "fail" if privileged and not s.allow_privileged_source_account else "ok",
                         f"user={who.get('username')} roles={roles}"))
    except SourceError as e:
        out.append(Check("es.account", "warn", f"cannot read identity: {e}"))
    concrete = []
    try:
        for pat in s.es_index_patterns:
            names = c.resolve(pat)
            concrete += names
            out.append(Check(f"es.index[{pat}]", "ok" if names else "fail", f"resolves to {names}"))
    except SourceError as e:
        out.append(Check("es.privileges", "warn", str(e)))
        out.append(Check("os.read_only", "warn", f"the index patterns could not be resolved ({e}), so "
                                                 f"_has_privileges was not asked: {READ_ONLY_UNPROVEN}"))
        return out
    if not concrete:
        out.append(Check("os.read_only", "warn", "no configured index pattern resolves to an index, so "
                                                 f"_has_privileges was not asked: {READ_ONLY_UNPROVEN}"))
        return out
    try:
        p = c.has_privileges(concrete)
    except SourceError as e:
        out.append(Check("es.privileges", "warn", str(e)))
        out.append(Check("os.read_only", "warn", f"_has_privileges could not be read ({e}): {READ_ONLY_UNPROVEN}"))
        return out
    cl = p.get("cluster", {})
    idx = p.get("index", {})
    writes = sorted({f"{i}:{k}" for i, privs in idx.items() for k, v in privs.items() if v and k != "read"})
    reads = [i for i, privs in idx.items() if privs.get("read")]
    bad_cluster = sorted(k for k in ES_CLUSTER_WRITE_PRIVILEGES if cl.get(k))
    status = "ok" if not writes and not bad_cluster else "fail"
    out.append(Check("es.least_privilege", status,
                     f"read on {len(reads)}/{len(concrete)} indices; write-capable={writes or 'none'}; "
                     f"cluster-write={bad_cluster or 'none'}"))
    out.append(Check("os.read_only", status,
                     "_has_privileges shows no write privilege on the configured indices or the cluster"
                     if status == "ok" else
                     f"_has_privileges shows write-capable={writes or 'none'}, cluster-write={bad_cluster or 'none'}"))
    return out


def check_flavor_version(s: Settings, backend: Backend, refusal: str | None) -> Check:
    """`os.flavor_version`: the cluster is the configured flavor, at a version ROMULUS pages through correctly:
    OpenSearch 2.4 or later (point in time), Elasticsearch 8 or later."""
    if refusal is not None:
        return Check("os.flavor_version", "fail", refusal)
    if s.es_flavor == "elasticsearch":
        if backend.version is None or backend.version[:2] < ELASTICSEARCH_MIN:
            return Check("os.flavor_version", "fail",
                         f"the cluster reports {backend.label()}: Elasticsearch 8 or later is required")
        return Check("os.flavor_version", "ok", f"{backend.label()} matches ES_FLAVOR=elasticsearch")
    detail = f"{backend.label()} matches ES_FLAVOR=opensearch; point-in-time search available"
    if backend.version is not None and backend.version[:2] < OPENSEARCH_SHARD_DOC:
        detail += ("; this version has no _shard_doc tiebreaker (3.3 or later), so records sharing one time value "
                   f"are read as a whole group; a group of more than {TIE_GROUP_WINDOW:,} records is read in part "
                   "and the search says so")
    return Check("os.flavor_version", "ok", detail)


def _check_opensearch_access(s: Settings, c: ElasticClient) -> list[Check]:
    """Account, index resolution and `os.read_only` on OpenSearch. OpenSearch has no has-privileges API: with
    the security plugin, read-only is shown only when every role it maps the account to is a role the site
    configured as read-only (ES_READ_ONLY_ROLES); without the plugin, or when it does not answer, it is a warning.
    It is never reported as read-only when that cannot be shown."""
    out: list[Check] = []
    try:
        who = c.authinfo()
    except SourceError as e:
        why = (f"the security plugin does not answer (HTTP {e.status})" if e.status in (400, 404, 405)
               else f"the security plugin refused to describe the account (HTTP {e.status})" if e.status in (401, 403)
               else f"the account could not be read: {e}")
        out.append(Check("es.account", "warn", f"{why}; the account and its roles are unknown"))
        out += _check_indices(s, c)
        out.append(Check("os.read_only", "warn", f"{why}: {READ_ONLY_UNPROVEN}"))
        return out
    user = who.get("user_name")
    roles = who.get("roles")
    roles = sorted({str(r) for r in roles}) if isinstance(roles, list) else []
    privileged = FULL_ACCESS_ROLE in roles
    out.append(Check("es.account", "fail" if privileged and not s.allow_privileged_source_account else "ok",
                     f"user={user} roles={roles} backend_roles={who.get('backend_roles')}"))
    out += _check_indices(s, c)
    configured = set(s.es_read_only_roles)
    if privileged:
        out.append(Check("os.read_only", "warn" if s.allow_privileged_source_account else "fail",
                         f"user={user} holds {FULL_ACCESS_ROLE}, which can write to every index"))
    elif not roles:
        out.append(Check("os.read_only", "warn", f"the security plugin lists no roles for user={user}: "
                                                 f"{READ_ONLY_UNPROVEN}"))
    elif not configured:
        out.append(Check("os.read_only", "warn", f"user={user} has roles {roles}, and no read-only role names are "
                                                 f"configured (ES_READ_ONLY_ROLES): {READ_ONLY_UNPROVEN}"))
    elif set(roles) <= configured:
        out.append(Check("os.read_only", "ok", f"every role of user={user} ({roles}) is a configured read-only role"))
    else:
        others = sorted(set(roles) - configured)
        out.append(Check("os.read_only", "warn", f"user={user} also has roles {others}, which are not configured "
                                                 f"read-only roles (ES_READ_ONLY_ROLES): {READ_ONLY_UNPROVEN}"))
    return out


def _check_indices(s: Settings, c: ElasticClient) -> list[Check]:
    out = []
    try:
        for pat in s.es_index_patterns:
            names = c.resolve(pat)
            out.append(Check(f"es.index[{pat}]", "ok" if names else "fail", f"resolves to {names}"))
    except SourceError as e:
        out.append(Check("es.index", "warn", str(e)))
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
                     f"{definition.summary()}; rules that depend on traffic direction report that they searched only in part "
                     "coverage")
    client = client or ElasticClient(s, timeout=ES_TIMEOUT)
    coverage = None
    try:
        site_facts = load_site_facts(s.home)
        contracts = {target: apply_zeek_declaration(
            contract_from_types(target, flatten_mapping(client.mapping(target))), site_facts)
            for pattern in s.es_index_patterns for target in client.resolve(pattern)}
        coverage = check_network_addresses(client, contracts, definition, None)
        result = check_host_addresses(client, contracts, definition, None)
        result["coverage"] = coverage
    except (SourceError, ValueError) as e:
        notes.append(f"{definition.summary()}; host addresses could not be checked: {e}")
        if coverage is None:
            coverage = {"status": "unknown", "warn": True, "outside": None, "outside_share": None,
                        "reasons": ["source inventory or mappings unavailable"],
                        "summary": "Network-address coverage unknown: source inventory or mappings unavailable."}
        notes.append(coverage["summary"])
        return Check("site.internal_networks", "warn", "; ".join(notes), data={"coverage": coverage})
    if not result["values_present"]:
        unchecked = "; ".join(f"{t}: {why}" for t, why in sorted(result["unchecked_targets"].items()))
        notes.append(f"{definition.summary()}; no host.ip value in host telemetry ({result['window']}), so the "
                     "definition could not be checked against the site's own hosts"
                     + (f" ({unchecked})" if unchecked else ""))
    elif not result["outside"]:
        notes.append(f"{definition.summary()}; every host.ip value in host telemetry ({result['window']}) is inside")
    if result["warning"]:
        notes.append(result["warning"])
    if coverage["status"] != "not_applicable":
        notes.append(coverage["summary"])
    status = "warn" if result["warning"] or coverage["warn"] or not definition.configured else "ok"
    return Check("site.internal_networks", status, "; ".join(notes), data=result)


def check_arkime(s: Settings, transport: httpx.BaseTransport | None = None) -> Check:
    """One read of the viewer's session list, through the same client, base path, authentication and endpoint
    allowlist the packet fetch uses."""
    path = "/api/sessions"
    try:
        check_arkime_endpoint("GET", path)
        with arkime_client(s, transport=transport, timeout=ARKIME_TIMEOUT) as http:
            r = http.get(path, params={"date": "1", "length": "1"})
        return Check("arkime.reachable", "ok" if r.status_code == 200 else "fail",
                     f"HTTP {r.status_code} ({s.arkime_auth} authentication, base path "
                     f"{s.arkime_base_path or '/'})")
    except (httpx.HTTPError, PacketError) as e:
        return Check("arkime.reachable", "fail", redact_text(str(e), s))


def check_arkime_auth(s: Settings) -> Check | None:
    """Basic authentication sends the password with every request: only over TLS."""
    if s.arkime_auth == "basic" and httpx.URL(s.arkime_url).scheme == "http":
        return Check("arkime.auth", "warn", "basic authentication over plain HTTP sends the Arkime password in "
                                            "clear on every request: use an https ARKIME_URL")
    return None


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
        v = httpx.get(f"{base}/api/version", timeout=OLLAMA_TIMEOUT).json().get("version")
        tags = [m["name"] for m in httpx.get(f"{base}/api/tags", timeout=OLLAMA_TIMEOUT).json().get("models", [])]
        out.append(Check("ollama.reachable", "ok", f"version {v}; models={tags}"))
        for model in {s.ollama_model_triage, s.synthesis_model}:
            if model not in tags:
                out.append(Check(f"ollama.model[{model}]", "fail", "not pulled"))
                continue
            show = httpx.post(f"{base}/api/show", json={"model": model}, timeout=OLLAMA_SHOW_TIMEOUT).json()
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
    openai_style = readiness.provider in ("openai_compatible", "openai_responses")
    if openai_style and not s.agent_context_tokens and d.egress == "local":
        out.append(Check("agent.context", "warn", "AGENT_CONTEXT_TOKENS is 0: a local server that silently cuts "
                                                  "long prompts cannot be detected; set it to the model's context window"))
    long_reasoning = s.agent_effort in LONG_REASONING_EFFORTS and s.agent_timeout_seconds < LONG_REASONING_TIMEOUT
    if readiness.provider == "openai_responses" and long_reasoning:
        out.append(Check("agent.timeout", "warn",
                         f"AGENT_TIMEOUT_SECONDS={s.agent_timeout_seconds} with AGENT_EFFORT={s.agent_effort}: a model "
                         "can reason without sending anything for longer than that, and a call that times out after "
                         f"it began is billed and fails; use {LONG_REASONING_TIMEOUT} or more"))
    # the probe's calls are cut at MODEL_PROBE_CALL_SECONDS; the agent.timeout warning above reads the configured value
    probe_settings = (s if s.agent_timeout_seconds <= MODEL_PROBE_CALL_SECONDS
                      else s.model_copy(update={"agent_timeout_seconds": MODEL_PROBE_CALL_SECONDS}))
    try:
        provider = build_provider(probe_settings, transport=transport, resolver=resolver, readiness=readiness)
    except AgentNotReady as exc:       # an optional SDK that cannot be loaded: not configured, never a traceback
        message = redact_text(str(exc), s)
        if message.startswith("agent not configured"):
            return [Check("agent.provider", "ok", f"{message}; hunts run without the AI agent")]
        return [*out, Check("agent.provider", "fail", message)]
    try:
        probes = provider.probe()
    except Exception as exc:  # noqa: BLE001 - a broken or hostile endpoint must not take the other checks down
        probes = [("agent.reachable", "fail", f"probe failed: {exc.__class__.__name__}: {exc}"[:300])]
    for name, status, detail in probes:
        out.append(Check(name, status, redact_text(detail, s)))
    return out


def check_triage_model(s: Settings, transport: httpx.BaseTransport | None = None,
                       resolver: Resolver = system_resolver) -> list[Check]:
    """The triage pass's model, when AGENT_TRIAGE_MODEL names one other than the agent's: the agent checks again for
    that model, reported as triage.* checks. Nothing when the triage pass uses the agent's model."""
    triage = triage_settings(s)
    if triage.agent_model == s.agent_model:
        return []
    return [Check("triage." + check.name.split(".", 1)[-1], check.status,
                  f"AGENT_TRIAGE_MODEL={triage.agent_model}: {check.detail}")
            for check in check_agent(triage, transport, resolver)]


def check_secret_lengths(s: Settings) -> Check:
    """Short secrets are redacted wherever their text turns up, ordinary words included. Names only: never a
    secret or its length."""
    short = short_secrets(s)
    if not short:
        return Check("secrets.length", "ok", f"configured secrets are at least {MIN_SECRET_LENGTH} characters")
    return Check("secrets.length", "warn",
                 f"{', '.join(short)}: shorter than {MIN_SECRET_LENGTH} characters. Text that short also turns up in "
                 "ordinary words, so redaction distorts prompts and reports (and very short secrets cannot be "
                 "redacted); use longer secrets")


# A secret-typed setting is weak when any of these measures holds (doctor warns, never fails):
# - it is under WEAK_SINGLE_CLASS_BELOW characters and uses one character class: all letters (either case), all
#   digits, or all other characters. Ordinary words are all letters. A longer single-class value is left to the
#   entropy measure, since a long random string of letters is strong.
# - its estimated entropy, its length times the Shannon entropy of its own character distribution, is under
#   WEAK_ENTROPY_BITS. The estimate is at most length x log2(length), so any value under about 12 characters scores
#   below the threshold (such a value is weak whatever its characters); a 32-character random key scores about 150.
# - it occurs as a whole word, in any case, in the product's own source or templates: public text the agent's secret
#   guard would also match.
# No wordlist is bundled with the product, so dictionary words are found by the first and last measures.
# Secrets shorter than MIN_SECRET_LENGTH are reported by check_secret_lengths instead.
WEAK_ENTROPY_BITS = 40.0
WEAK_SINGLE_CLASS_BELOW = 32
SOURCE_SUFFIXES = frozenset({".py", ".html", ".md", ".js", ".css", ".mako", ".txt", ".json", ".yml", ".yaml",
                             ".toml", ".sql", ".j2"})
SOURCE_FILE_MAX_BYTES = 8 * 2**20
COARSE_LENGTH = 16     # the only length a warning gives: "under 16 characters"
_WORD = "A-Za-z0-9_"


def _entropy_bits(value: str) -> float:
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -n * sum(c / n * math.log2(c / n) for c in counts.values())


def _single_class(value: str) -> bool:
    classes = {"letter" if ch.isalpha() else "digit" if ch.isdigit() else "other" for ch in value}
    return len(classes) == 1


def _source_words(values: list[str], root: Path) -> set[str]:
    """The values that occur as a whole word (any case) in the text files under `root`. Each file is read once."""
    pending = {value: re.compile(rf"(?<![{_WORD}]){re.escape(value)}(?![{_WORD}])", re.IGNORECASE)
               for value in values}
    found: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not pending:
            break
        try:
            if path.suffix.lower() not in SOURCE_SUFFIXES or not path.is_file() \
                    or path.stat().st_size > SOURCE_FILE_MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = text.lower()
        for value, pattern in list(pending.items()):
            if value.lower() in lowered and pattern.search(text):
                found.add(value)
                del pending[value]
    return found


def check_secret_strength(s: Settings, source_root: Path | None = None) -> Check:
    """Warn about secret-typed settings that are low-entropy or dictionary-like (the measures above). Names only:
    never a value, which measure fired, or a length beyond "under 16 characters"."""
    secrets = [(name, value) for name, value in secret_settings(s) if len(value) >= MIN_SECRET_LENGTH]
    if not secrets:
        return Check("secrets.strength", "ok", "no secret long enough to judge is configured")
    weak = {name for name, value in secrets
            if (len(value) < WEAK_SINGLE_CLASS_BELOW and _single_class(value))
            or _entropy_bits(value) < WEAK_ENTROPY_BITS}
    rest = [value for name, value in secrets if name not in weak]
    if rest:
        in_source = _source_words(rest, source_root or Path(__file__).resolve().parent)
        weak |= {name for name, value in secrets if value in in_source}
    if not weak:
        return Check("secrets.strength", "ok", "no configured secret is low-entropy or dictionary-like")
    shown = ", ".join(f"{name} (under {COARSE_LENGTH} characters)" if len(value) < COARSE_LENGTH else name
                      for name, value in secrets if name in weak)
    return Check("secrets.strength", "warn",
                 f"{shown}: low-entropy or dictionary-like. A weak secret is easier to guess, and the AI agent's "
                 "secret guard matches its text wherever it appears: telemetry holding that text is redacted before "
                 "the model sees it, hiding parts of those records, and a model reply that writes it ends that "
                 "investigation session. Use a long random value", {"settings": sorted(weak)})


def check_tshark(s: Settings) -> Check:
    exe = shutil.which(s.tshark_bin)
    if not exe:
        return Check("tshark", "fail", f"{s.tshark_bin} not found")
    try:
        v = subprocess.run(
            [exe, "--version"], check=False, capture_output=True, text=True, timeout=TSHARK_SECONDS
        ).stdout.splitlines()[:1]
    except subprocess.TimeoutExpired:
        return Check("tshark", "fail", f"{exe} --version did not finish within {TSHARK_SECONDS} s")
    except OSError as e:
        return Check("tshark", "fail", f"{exe} could not be run: {e}")
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


def _store_unreadable(name: str, path: Path, error: Exception) -> Check:
    """A store that could not be read: a lock held past the busy wait is a warning (nothing was verified), any other
    error a failure."""
    text = str(getattr(error, "orig", None) or error)
    if any(word in text.lower() for word in ("locked", "busy")):
        return Check(name, "warn", f"{path}: another process held a lock for more than "
                                   f"{DB_BUSY_TIMEOUT_MS / 1000:g} s ({text}); not verified")
    if any(word in text.lower() for word in ("unable to open", "readonly", "read-only")):
        # a read-only open of a WAL store needs its -wal/-shm side files; a user who cannot create them in the store's
        # folder (no process has the store open) cannot read it here, which says nothing about the store itself
        return Check(name, "warn", f"{path}: could not be opened read-only by this user ({text}); not verified. "
                                   "Run doctor as the store's owner, or while the web or a hunt has the store open")
    return Check(name, "fail", f"{path}: cannot be read: {text}")


def check_db(s: Settings, seconds: float = DB_INTEGRITY_SECONDS) -> Check:
    """`db.integrity`: SQLite's integrity check over a read-only connection that never migrates or writes, so it waits
    behind no writer (a reader in WAL mode does not), and stops at `seconds`. Its schema version is compared with this
    build's; a store that is behind is a warning (the next command that opens it for work migrates it)."""
    path = Path(s.db_path)
    if not path.exists():
        return Check("db.integrity", "warn", f"{path}: no database yet; it is created on first use")
    engine = make_read_only_engine(path, busy_timeout_ms=DB_BUSY_TIMEOUT_MS)
    try:
        current, expected = schema_heads(engine)
        res = integrity_check(engine, seconds=seconds)
    except IntegrityCheckTimeout:
        return Check("db.integrity", "warn", f"{path}: the integrity check did not finish within {seconds:g} s and was "
                                             "stopped; integrity not verified (doctor --check-timeout allows longer)")
    except (sa_exc.DBAPIError, sqlite3.Error) as error:
        return _store_unreadable("db.integrity", path, error)
    finally:
        engine.dispose()
    if res != "ok":
        return Check("db.integrity", "fail", f"{path}: {res}")
    if current != expected:
        return Check("db.integrity", "warn", f"{path}: ok; schema at {', '.join(sorted(current)) or 'none'}, this build "
                                             f"expects {', '.join(sorted(expected))}: the next command that opens the "
                                             "store for work migrates it")
    return Check("db.integrity", "ok", f"{path}: {res}")


def check_db_space(s: Settings) -> Check:
    """Warn when most of the database file is reclaimable (free pages or an oversized write-ahead log)."""
    path = Path(s.db_path)
    if not path.exists():
        return Check("db.space", "ok", f"{path}: no database yet")
    engine = make_read_only_engine(path, busy_timeout_ms=DB_BUSY_TIMEOUT_MS)
    try:
        rep = space_report(engine)
    except (sa_exc.DBAPIError, sqlite3.Error) as error:
        return _store_unreadable("db.space", path, error)
    finally:
        engine.dispose()
    reclaim = rep["free_bytes"] + rep["wal_bytes"]
    total = rep["file_bytes"] + rep["wal_bytes"]
    detail = (f"file {rep['file_bytes'] / 1e6:.0f} MB, write-ahead log {rep['wal_bytes'] / 1e6:.0f} MB, "
              f"reclaimable {reclaim / 1e6:.0f} MB")
    big = reclaim > 200e6 and total and reclaim / total > 0.5
    return Check("db.space", "warn" if big else "ok",
                 detail + ("; run `romulus db compact` when no hunt is running" if big else ""))


def check_site(s: Settings) -> Check:
    from romulus.site import role_address_warnings

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
    warnings = role_address_warnings(facts.content)
    return Check(
        "site.collection",
        "warn" if warnings else "ok",
        f"valid; {len(facts.groups)} collection group(s)" + ("; " + "; ".join(warnings) if warnings else ""),
        {"digest": facts.digest, "groups": len(facts.groups), "warnings": warnings},
    )


def check_linux_text_sources(s: Settings, client: ElasticClient | None = None) -> list[Check]:
    """List native Windows shapes and potential text samples, separately from typed coverage."""
    client = client or ElasticClient(s, timeout=ES_TIMEOUT)
    out = []
    try:
        site_facts = load_site_facts(s.home) if s.home is not None else None
        targets = sorted({target for pattern in s.es_index_patterns for target in client.resolve(pattern)})
    except (SourceError, SiteValidationError) as error:
        return [Check("es.text_inventory", "warn", f"text source inventory unavailable: {error}")]
    for target in targets:
        try:
            profile, _contract = build_profile(client, target, site_facts=site_facts)
        except SourceError as error:
            out.append(Check(f"es.text_inventory[{target}]", "warn", f"text source inventory unavailable: {error}"))
            continue
        shapes = profile.model_dump().get("windows_shapes") or {}
        classification = [note for note in profile.notes if note.startswith((
            "Windows classification unverified", "Windows event records on a network target"))]
        if classification:
            out.append(Check(f"es.windows_classification[{target}]", "warn", "; ".join(classification)))
        if temporal := profile.model_dump().get("temporal_gaps"):
            out.append(Check(f"es.temporal_coverage[{target}]", "warn", "; ".join(item["reason"] for item in temporal),
                             {"gaps": temporal}))
        if shapes:
            parts = [f"{shape}: {detail['records'] if detail['records'] is not None else 'unknown'} source records"
                     + (f"; {detail['reason']}" if detail.get("reason") else "")
                     for shape, detail in sorted(shapes.items())]
            out.append(Check(f"es.windows_inventory[{target}]",
                             "ok" if all(detail["complete"] for detail in shapes.values()) else "warn",
                             "; ".join(parts), shapes))
        detail = profile.model_dump().get("linux_text")
        inventory_notes = [note for note in profile.notes
                           if note.startswith("ds inventory truncated (data_stream.dataset")]
        if not detail:
            if inventory_notes:
                out.append(Check(f"es.text_inventory[{target}]", "warn", "; ".join(inventory_notes)))
            continue
        parts = list(inventory_notes)
        complete = not inventory_notes
        samples = [(name, detail["inventory"][name], sample) for name, sample in detail["samples"].items()]
        if "datasetless" in detail:
            sample = detail["datasetless"]
            samples.append(("no dataset value", sample["records"], sample))
        for name, records, sample in samples:
            formats = ", ".join(f"{key}={value}" for key, value in sample["formats"].items()) or "none"
            programs = ", ".join(f"{key}={value}" for key, value in sample["programs"].items()) or "none"
            parts.append(f"{name}: {records if records is not None else 'unknown'} potential source records; "
                         f"sampled {sample['sampled']}; formats {formats}; programs {programs}"
                         + ("; " + "; ".join(sample["notes"]) if sample["notes"] else ""))
            complete = complete and sample["complete"] and not any(
                sample["formats"].get(name) for name in ("unknown", "too_long", "no_text_payload")
            )
        out.append(Check(f"es.text_inventory[{target}]", "ok" if complete else "warn", "; ".join(parts), detail))
    return out


@dataclass(frozen=True)
class Step:
    """One check (or group of checks) run under its own deadline. `name` is the check a timeout or an unexpected
    error is reported as; `critical` makes either a failure instead of a warning."""
    name: str
    run: Callable[[], Check | list[Check] | None]
    seconds: float
    critical: bool


def run_step(step: Step, s: Settings) -> list[Check]:
    """Run one step in a daemon thread and wait at most its deadline. A step still running then is reported as timed
    out and left behind (a daemon thread never holds the process open, and every client it uses has its own timeouts);
    an exception is reported as the step's result. Neither stops the checks after it."""
    box: dict = {}

    def target() -> None:
        try:
            box["value"] = step.run()
        except BaseException as exc:  # noqa: BLE001 - every failure of a check is that check's result
            box["error"] = exc

    worker = threading.Thread(target=target, name=f"doctor:{step.name}", daemon=True)
    worker.start()
    worker.join(step.seconds)
    status = "fail" if step.critical else "warn"
    if worker.is_alive():
        return [Check(step.name, status, f"timed out after {step.seconds:g} s; not verified",
                      {"timed_out": True, "seconds": step.seconds})]
    if "error" in box:
        error = box["error"]
        return [Check(step.name, status, redact_text(f"check failed: {type(error).__name__}: {error}", s)[:500])]
    value = box.get("value")
    if value is None:
        return []
    return [value] if isinstance(value, Check) else list(value)


def doctor_steps(s: Settings, env_file: Path | None = None, check_seconds: float | None = None) -> list[Step]:
    """The checks run_all runs, in order, each with its deadline (`check_seconds`, when given, for every one)."""
    def bound(seconds: float) -> float:
        return check_seconds if check_seconds is not None else seconds

    integrity = bound(DB_INTEGRITY_SECONDS)
    return [
        Step("es.reachable", lambda: check_es(s), bound(CHECK_SECONDS), True),
        Step("es.text_inventory", lambda: check_linux_text_sources(s), bound(INVENTORY_SECONDS), False),
        Step("site.internal_networks", lambda: check_site_networks(s), bound(INVENTORY_SECONDS), False),
        Step("arkime.reachable", lambda: check_arkime(s), bound(LOCAL_SECONDS), True),
        Step("arkime.auth", lambda: check_arkime_auth(s), bound(LOCAL_SECONDS), False),
        Step("ollama.reachable", lambda: check_ollama(s), bound(CHECK_SECONDS), True),
        Step("agent.provider", lambda: check_agent(s), bound(MODEL_SECONDS), True),
        Step("triage.provider", lambda: check_triage_model(s), bound(MODEL_SECONDS), True),
        Step("secrets.length", lambda: check_secret_lengths(s), bound(LOCAL_SECONDS), False),
        Step("secrets.strength", lambda: check_secret_strength(s), bound(CHECK_SECONDS), False),
        Step("tshark", lambda: check_tshark(s), bound(LOCAL_SECONDS), True),
        Step("paths", lambda: check_paths(s, env_file), bound(LOCAL_SECONDS), False),
        Step("site.collection", lambda: check_site(s), bound(LOCAL_SECONDS), False),
        Step("db.integrity", lambda: check_db(s, integrity), integrity + DB_GRACE_SECONDS, False),
        Step("db.space", lambda: check_db_space(s), bound(LOCAL_SECONDS), False),
    ]


def run_all(s: Settings, env_file: Path | None = None, *, check_seconds: float | None = None,
            on_check: Callable[[Check], None] | None = None) -> list[Check]:
    """Every check, each under its own deadline (doctor_steps). `on_check` is called with each result as it is
    known, so a slow check is seen while it runs."""
    checks: list[Check] = []
    for step in doctor_steps(s, env_file, check_seconds):
        for check in run_step(step, s):
            checks.append(check)
            if on_check is not None:
                on_check(check)
    return checks
