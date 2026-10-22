"""Pure baseline specifications, canonical keys, and unresolved process-parent carry-in."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from romulus.detect.correlation import PidTable, boot_of, boots_conflict
from romulus.detect.dns import endpoints as dns_endpoints
from romulus.detect.dns import question_names, registered_domain
from romulus.detect.dns import role as dns_role
from romulus.detect.host import WEB_SERVICE_USERS
from romulus.evidence.typed import Outcome, TypedEvent

type Scope = Literal["host", "account", "host_account", "internal_ip", "site"]
type Measure = Literal["presence", "prevalence", "rate"]
type Bucket = Literal["day", "hour"]


@dataclass(frozen=True)
class BaselineKey:
    """One canonical key within an explicit scope.

    `key_digest` identifies the key within its scope (sha256 of spec, key version, scope and key); `key_id`
    identifies the key regardless of scope (sha256 of spec, key version and key), so prevalence counts the
    distinct scopes of one `scope_kind` that hold a `key_id` without parsing scope strings."""

    scope_kind: Scope
    scope: str
    key: dict[str, Any]
    key_digest: str
    key_id: str


@dataclass(frozen=True)
class Pending:
    """A process parent whose latest exec may exist only in pre-window carry-in."""

    host: str
    boot: str | None
    ppid: int
    ts: datetime


type KeyResult = list[BaselineKey] | Pending | None


@dataclass(frozen=True)
class KeyContext:
    """State supplied to otherwise-pure extractors; no source adapter is reachable here."""

    pid_table: PidTable = field(default_factory=PidTable)
    service_accounts: frozenset[str] = field(default_factory=lambda: frozenset(WEB_SERVICE_USERS))


@dataclass(frozen=True)
class BaselineSpec:
    """Versioned typed-field contract and key extractor for one baseline behavior."""

    id: str
    version: str
    key_version: str
    families: tuple[str, ...]
    datasets: tuple[str, ...]
    scope: Scope | tuple[Scope, ...]
    measure: Measure
    bucket: Bucket
    required_fields: dict[str, tuple[str, ...]]
    _extract: Callable[[TypedEvent, KeyContext, BaselineSpec], KeyResult] = field(repr=False, compare=False)

    def keys(self, event: TypedEvent, context: KeyContext) -> KeyResult:
        if event.family not in self.families:
            return None
        return self._extract(event, context, self)


def canonical_json(value: Any) -> str:
    """Canonical JSON spelling used in every key digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _contains_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_contains_missing(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_missing(item) for item in value)
    return False


def _sha256(material: str) -> str:
    return hashlib.sha256(material.encode()).hexdigest()


def key_id_of(spec_id: str, key_version: str, key: dict[str, Any]) -> str:
    """Scope-free key identity: sha256(spec_id|key_version|canonical-json(key))."""
    return _sha256(f"{spec_id}|{key_version}|{canonical_json(key)}")


def key_digest_of(spec_id: str, key_version: str, scope: str, key: dict[str, Any]) -> str:
    """Scoped key identity: sha256(spec_id|key_version|scope|canonical-json(key))."""
    return _sha256(f"{spec_id}|{key_version}|{scope}|{canonical_json(key)}")


def _key(spec: BaselineSpec, scope: tuple[Scope, str], key: dict[str, Any]) -> BaselineKey:
    kind, label = scope
    if not label or _contains_missing(key):
        raise ValueError("baseline keys cannot contain missing values")
    ordered = {name: key[name] for name in sorted(key)}
    return BaselineKey(
        scope_kind=kind, scope=label, key=ordered,
        key_digest=key_digest_of(spec.id, spec.key_version, label, ordered),
        key_id=key_id_of(spec.id, spec.key_version, ordered),
    )


def _scope(kind: Scope, **values: str) -> tuple[Scope, str]:
    """(scope kind, scope label). The label is unique across kinds; consumers group by the kind column."""
    if kind == "site":
        return "site", "site"
    if kind in {"host", "account", "internal_ip"}:
        return kind, f"{kind}:{next(iter(values.values()))}"
    return kind, f"host_account:{canonical_json(values)}"


def _canon_ip(value: Any) -> tuple[str, str] | None:
    if value in (None, ""):
        return None
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    prefix = 24 if address.version == 4 else 48
    return str(address), str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _canon_dns(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    return name or None


def _ssh_tuple(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    host, account = event.host, event.get("user.name")
    address = _canon_ip(event.get("source.ip"))
    if (event.outcome != Outcome.success or event.get("auth.service") != "sshd" or not host
            or account in (None, "") or address is None):
        return None
    ip, network = address
    account = str(account)
    site = _scope("site")
    return [
        _key(spec, site, {
            "kind": "tuple", "host": host, "source_ip": ip, "source_network": network, "user": account,
        }),
        _key(spec, site, {"kind": "host", "host": host}),
        _key(spec, site, {"kind": "source_ip", "source_ip": ip}),
        _key(spec, site, {"kind": "source_network", "source_network": network}),
        _key(spec, site, {"kind": "user", "user": account}),
    ]


def _exec_path(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    executable = event.get("process.executable")
    path = event.get("process.exec_file.path")
    account = event.get("process.user")
    if (event.outcome != Outcome.success or not event.host or executable in (None, "")
            or path in (None, "") or account in (None, "")):
        return None
    key = {"executable": str(executable), "exec_file_path": str(path)}
    return [
        _key(spec, _scope("host", host=event.host), key),
        _key(spec, _scope("account", account=str(account)), key),
    ]


def _exec_pair(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    executable, ppid = event.get("process.executable"), event.get("process.ppid")
    if not event.host or executable in (None, "") or not isinstance(ppid, int):
        return None
    boot = boot_of(event)
    parent = context.pid_table.lookup(event.host, ppid, event.ts.timestamp(), boot)
    if parent is None or boots_conflict(boot, parent[4]):
        return Pending(event.host, boot, ppid, event.ts)
    return [_key(spec, _scope("host", host=event.host), {
        "parent_executable": parent[1], "child_executable": str(executable),
    })]


_UUID = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![0-9a-f])")
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_BRACKETED_IP = re.compile(r"\[([0-9a-fA-F:.]+)\]")
_HEX_PREFIX = re.compile(r"(?i)(?<![0-9a-z])0x[0-9a-f]+(?![0-9a-z])")
_HEX_BARE = re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{8,}(?![0-9a-z])")
_NUMBER = re.compile(r"(?<![0-9a-zA-Z])[-+]?\d+(?:\.\d+)?(?![0-9a-zA-Z])")


def _replace_ipv4(match: re.Match[str]) -> str:
    return "<ip>" if _canon_ip(match.group(0)) is not None else match.group(0)


def _replace_bracketed_ip(match: re.Match[str]) -> str:
    return "[<ip>]" if _canon_ip(match.group(1)) is not None else match.group(0)


def _replace_bare_hex(match: re.Match[str]) -> str:
    value = match.group(0)
    return "<hex>" if any(character.lower() in "abcdef" for character in value) else value


def mask_argv_token(value: str) -> str:
    """Mask variable identifiers within one already-tokenized argv value."""
    token = _UUID.sub("<uuid>", value)
    if _canon_ip(token) is not None:
        return "<ip>"
    if "=" in token:
        prefix, candidate = token.rsplit("=", 1)
        if _canon_ip(candidate) is not None:
            return f"{prefix}=<ip>"
    token = _BRACKETED_IP.sub(_replace_bracketed_ip, token)
    token = _IPV4.sub(_replace_ipv4, token)
    token = _HEX_PREFIX.sub("<hex>", token)
    token = _HEX_BARE.sub(_replace_bare_hex, token)
    return _NUMBER.sub("<num>", token)


def _cmd_shape(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    executable, argv = event.get("process.executable"), event.get("process.argv")
    if (not event.host or executable in (None, "") or event.get("process.argv_complete") is False
            or not isinstance(argv, list) or not argv or not all(isinstance(token, str) for token in argv)):
        return None
    return [_key(spec, _scope("host", host=event.host), {
        "executable": str(executable), "argv_shape": [mask_argv_token(token) for token in argv],
    })]


def _destination(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    if event.family == "dns_query":
        record_role = dns_role(event)
        if record_role is None:
            return None
        source, _resolver = dns_endpoints(event, record_role)
        names = question_names(event) or []
        source_ip = _canon_ip(source)
        if not names or source_ip is None:
            return None
        # A lookup's destination is the name asked, never the resolver that answered it.
        scope = _scope("internal_ip", address=source_ip[0])
        return [_key(spec, scope, {"kind": "registered_domain", "registered_domain": registered_domain(name)})
                for name in names]
    source_ip, destination_ip = _canon_ip(event.get("source.ip")), _canon_ip(event.get("destination.ip"))
    if source_ip is None or destination_ip is None:
        return None
    scope = _scope("internal_ip", address=source_ip[0])
    keys = [
        _key(spec, scope, {"kind": "dest_ip", "dest_ip": destination_ip[0]}),
        _key(spec, scope, {"kind": "dest_network", "dest_network": destination_ip[1]}),
    ]
    sni = _canon_dns(event.get("tls.client.server_name"))
    if sni is not None:
        keys.append(_key(spec, scope, {"kind": "sni", "sni": sni}))
        keys.append(_key(spec, scope, {"kind": "registered_domain", "registered_domain": registered_domain(sni)}))
    return keys


def _service_rate(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    account = event.get("process.user")
    if not event.host or account in (None, "") or str(account) not in context.service_accounts:
        return None
    return [_key(spec, _scope("host_account", host=event.host, account=str(account)), {})]


BASELINE_SPECS = (
    BaselineSpec(
        id="bl.ssh_tuple", version="1", key_version="1", families=("auth",),
        datasets=("systemd.journal",), scope="site", measure="presence", bucket="day",
        required_fields={"auth": ("auth.service", "source.ip", "user.name")}, _extract=_ssh_tuple,
    ),
    BaselineSpec(
        id="bl.exec_path", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope=("host", "account"), measure="prevalence", bucket="day",
        required_fields={
            "process_exec": ("process.executable", "process.exec_file.path", "process.user"),
        }, _extract=_exec_path,
    ),
    BaselineSpec(
        id="bl.exec_pair", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host", measure="prevalence", bucket="day",
        required_fields={"process_exec": ("process.executable", "process.ppid")}, _extract=_exec_pair,
    ),
    BaselineSpec(
        id="bl.cmd_shape", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host", measure="prevalence", bucket="day",
        required_fields={"process_exec": ("process.executable", "process.argv")}, _extract=_cmd_shape,
    ),
    BaselineSpec(
        id="bl.ext_dest", version="1", key_version="1",
        families=("net_flow", "dns_query", "tls_session", "net_session"),
        datasets=(
            "suricata.eve.flow", "suricata.eve.netflow", "suricata.eve.dns", "suricata.eve.tls",
            "arkime.session",
        ),
        scope="internal_ip", measure="prevalence", bucket="day",
        required_fields={
            "net_flow": ("source.ip", "destination.ip"),
            "dns_query": ("source.ip", "destination.ip", "dns.question.name"),
            "tls_session": ("source.ip", "destination.ip"),
            "net_session": ("source.ip", "destination.ip"),
        },
        _extract=_destination,
    ),
    BaselineSpec(
        id="bl.svc_exec_rate", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host_account", measure="rate", bucket="hour",
        required_fields={"process_exec": ("process.user",)}, _extract=_service_rate,
    ),
)

SPEC_BY_ID = {spec.id: spec for spec in BASELINE_SPECS}
