"""Pure baseline specifications, canonical keys, and unresolved process-parent carry-in.

An extractor answers one of four ways for an event of one of its families:

- a non-empty list of `BaselineKey`: the event is counted under every key;
- `Pending`: an exec whose parent exec may sit before the window; a later stage resolves it from carry-in;
- `NotApplicable(reason)`: the event is outside the spec's behavior (a failed login, another service, an
  east-west flow). It is decided from typed values that are present and is never a coverage gap;
- `Missing(reason, fields)`: a value the spec needs is absent, malformed or not a scalar, so the event could
  not be evaluated. A missing value never becomes a key, and a stage counting `Missing` results can never
  report a complete negative for the scope.

When a present value already proves the event is not applicable, that answer wins over a missing value.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

from romulus.detect import netdef
from romulus.detect.correlation import PidTable, boot_of, boots_conflict
from romulus.detect.dns import registered_domain
from romulus.detect.dns import role as dns_role
from romulus.detect.dns import server_side as dns_server_side
from romulus.evidence.typed import Outcome, TypedEvent

type Scope = Literal["host", "account", "host_account", "internal_ip", "site"]
# "prevalence" specs are judged on presence in their own scope and on how many peer scopes of the same kind
# hold the key; "presence" specs only on their own scope; "rate" specs on an hourly count series.
type Measure = Literal["presence", "prevalence", "rate"]
type Bucket = Literal["day", "hour"]
type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# A required-field entry is one typed field, or a tuple of alternatives of which any one suffices.
type FieldRequirement = str | tuple[str, ...]


@dataclass(frozen=True)
class BaselineKey:
    """One canonical key within an explicit scope.

    `key_digest` identifies the key within its scope (sha256 of spec, key version, scope and key); `key_id`
    identifies the key regardless of scope (sha256 of spec, key version and key), so prevalence counts the
    distinct scopes of one `scope_kind` that hold a `key_id` without parsing scope strings.

    `dedup_token` is the counting rule: a counter counts a key once per distinct non-None token, and once per
    record when the token is None. Records of one network flow share a token (a flow record and the TLS record
    of the same connection count once), and the query and answer records of one DNS transaction share one
    (flow, question names and the DNS id when typed), so a transaction logged as both counts once. A record
    without a typed flow identity cannot be proven part of another record's flow and counts on its own.
    Tokens are only shared between records of one flow, so a counter can expire them after the flow timeout."""

    scope_kind: Scope
    scope: str
    key: dict[str, Any]
    key_digest: str
    key_id: str
    dedup_token: str | None = None


@dataclass(frozen=True)
class Pending:
    """An exec whose parent's exec is not in the supplied pid table: it may exist only in pre-window carry-in.

    Compact by design, so a later stage can stage pendings to disk instead of holding child events: the
    recorded host (the pid-table key), boot, parent pid and child time to look the parent up, the child's
    event id to cite, and the child executable that completes the key."""

    host: str
    boot: str | None
    ppid: int
    ts: datetime
    event_id: str
    child_executable: str
    # The child's audit serial: it places the child among its parent's execs at the same instant.
    serial: int | None = None
    # Source identities are sufficient to fetch the child's record only if its key is published.
    raw_refs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class NotApplicable:
    """The event is outside the spec's behavior, decided from typed values that are present."""

    reason: str


@dataclass(frozen=True)
class Missing:
    """A value the spec needs is absent, malformed or not a scalar; the event was not evaluated."""

    reason: str
    fields: tuple[str, ...]


type KeyResult = list[BaselineKey] | Pending | NotApplicable | Missing


@runtime_checkable
class ParentLookup(Protocol):
    """The only pid-table operation extractors use, so a bounded or disk-backed table can stand in.

    Returns `(exec_ts, executable, parent_pid, raw_id, boot)` for the latest exec of `pid` on `host` at or
    before `ts` in `boot`, or None."""

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None) -> tuple | None: ...


def exec_serial(event: TypedEvent) -> int | None:
    """The record's audit serial, which increases within a boot; None when absent or not an integer."""
    value = event.get("audit.serial")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parent_at(table: ParentLookup, host: str, pid: int, ts: float, boot: str | None,
              serial: int | None):
    """The parent identity for a child at (ts, serial). A table that orders one instant's execs by audit serial
    (`lookup_ordered`) is asked with the child's serial; any other table is asked by time alone."""
    ordered = getattr(table, "lookup_ordered", None)
    if ordered is not None:
        return ordered(host, pid, ts, boot, serial)
    return table.lookup(host, pid, ts, boot)


# Accounts whose uid falls in this range are system (service) accounts: 1-999 is the default SYS_UID_MIN to
# SYS_UID_MAX of login.defs on common Linux distributions, where package-created daemons (postgres, jenkins,
# www-data) get their uids. uid 0 (root) is never a service account here: root's activity is every
# administrator's and every boot's, so an hourly root rate says nothing about one service.
DEFAULT_SYSTEM_UID_RANGE = (1, 999)


@dataclass(frozen=True)
class KeyContext:
    """State supplied to otherwise-pure extractors; no source adapter is reachable here.

    - `pid_table`: parent exec lookups for `bl.exec_pair`;
    - `service_accounts`: account names configured as service accounts, keyed by `bl.svc_exec_rate`
      whatever their uid (empty by default: the uid range does the work);
    - `system_uid_range`: inclusive uid range of system accounts;
    - `is_internal`: whether an address belongs to the site. The default is the internal-network definition
      installed when the context is built (romulus.detect.netdef: the site's configured ranges, or the RFC
      1918 and reserved default), so one context answers with one definition throughout."""

    pid_table: ParentLookup = field(default_factory=PidTable)
    service_accounts: frozenset[str] = frozenset()
    system_uid_range: tuple[int, int] = DEFAULT_SYSTEM_UID_RANGE
    is_internal: Callable[[IPAddress], bool] = field(default_factory=lambda: netdef.current().is_internal)


@dataclass(frozen=True)
class BaselineSpec:
    """Versioned typed-field contract and key extractor for one baseline behavior.

    `required_fields` names, per family, the typed fields without which an event of that family is `Missing`
    (a tuple entry is a group of alternatives). Every spec also needs the event's host, and specs that
    judge an outcome need a known outcome. `optional_fields` are read when present. Both drive source-profile
    applicability and retrieval projection before any event is read; `Missing` reports the per-event result."""

    id: str
    version: str
    key_version: str
    families: tuple[str, ...]
    datasets: tuple[str, ...]
    scope: Scope | tuple[Scope, ...]
    measure: Measure
    bucket: Bucket
    required_fields: dict[str, tuple[FieldRequirement, ...]]
    optional_fields: dict[str, tuple[str, ...]]
    _extract: Callable[[TypedEvent, KeyContext, BaselineSpec], KeyResult] = field(repr=False, compare=False)
    # True when the spec's applicability is decided by the site's boundary (inside to outside): it may run only
    # with an explicitly configured internal-network definition, and otherwise its result is unresolved, never
    # "no match" (the default RFC 1918 view reads a site in public space as entirely outside).
    requires_configured_networks: bool = False

    def keys(self, event: TypedEvent, context: KeyContext) -> KeyResult:
        if event.family not in self.families:
            return NotApplicable(f"family {event.family} is not one of {', '.join(self.families)}")
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


def _host(event: TypedEvent) -> str | Missing:
    """The event's host for a scope: lower-cased, since host names are case-insensitive."""
    host = event.host
    if not isinstance(host, str) or not host.strip():
        return Missing("no host recorded", ("host",))
    return host.strip().lower()


def _text(event: TypedEvent, name: str) -> str | Missing:
    """A required non-empty string value, verbatim."""
    value = event.get(name)
    if value is None or value == "":
        return Missing(f"{name} is absent", (name,))
    if not isinstance(value, str):
        return Missing(f"{name} is a {type(value).__name__}, not a single string", (name,))
    return value


def _parse_ip(value: Any) -> IPAddress | None:
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        return None
    # An IPv6 zone id (fe80::1%eth0) names the observer's interface, not the address.
    value = value.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _canon_ip(value: Any) -> tuple[str, str] | None:
    address = _parse_ip(value)
    if address is None:
        return None
    prefix = 24 if address.version == 4 else 48
    return str(address), str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _ip(event: TypedEvent, name: str) -> IPAddress | Missing:
    value = event.get(name)
    if value is None or value == "":
        return Missing(f"{name} is absent", (name,))
    address = _parse_ip(value)
    if address is None:
        return Missing(f"{name} is not an IP address", (name,))
    return address


def _network(address: IPAddress) -> str:
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _dns_name(value: str) -> str | None:
    """Canonical DNS name: trimmed, lower-case, no trailing dot, internationalized labels as punycode
    A-labels; '.' for the root; None when empty. Raises ValueError for a name IDNA cannot encode."""
    text = value.strip()
    if text in ("<root>", "."):
        return "."
    name = text.rstrip(".").lower()
    if name and not name.isascii():
        try:
            name = name.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError(f"{value!r} is not an encodable internationalized name") from error
    return name or None


def _registrable(name: str) -> str | None:
    """The registered domain of a canonical name, or None for the root and for an address literal."""
    if name == "." or _parse_ip(name.removeprefix("[").removesuffix("]")) is not None:
        return None
    return registered_domain(name)


def _unique(keys: list[BaselineKey]) -> list[BaselineKey]:
    """Identical keys from one event count once (two question names in one registered domain, say)."""
    seen: set[str] = set()
    return [key for key in keys if not (key.key_digest in seen or seen.add(key.key_digest))]


def _flow_identity(event: TypedEvent) -> list[str] | None:
    """The record's flow: the sensor's flow id, else the community id; None when neither is typed."""
    for name in ("suricata.flow_id", "network.community_id"):
        value = event.get(name)
        if value not in (None, "") and not isinstance(value, (bool, list, dict)):
            return [name, str(value)]
    return None


def _with_token(keys: list[BaselineKey], token: str | None) -> list[BaselineKey]:
    return [replace(key, dedup_token=token) for key in keys]


def _outcome_success(event: TypedEvent, action: str) -> NotApplicable | Missing | None:
    if event.outcome == Outcome.failure:
        return NotApplicable(f"the {action} failed")
    if event.outcome != Outcome.success:
        return Missing(f"the {action} outcome is not recorded", ("outcome",))
    return None


def _ssh_tuple(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    service = event.get("auth.service")
    if event.outcome == Outcome.failure:
        return NotApplicable("the authentication failed")
    if isinstance(service, str) and service and service != "sshd":
        return NotApplicable(f"service {service} is not sshd")
    service = _text(event, "auth.service")
    if isinstance(service, Missing):
        return service
    if (outcome := _outcome_success(event, "authentication")) is not None:
        return outcome
    host, address, account = _host(event), _ip(event, "source.ip"), _text(event, "user.name")
    for value in (host, address, account):
        if isinstance(value, Missing):
            return value
    ip, network = str(address), _network(address)
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
    if (outcome := _outcome_success(event, "exec")) is not None:
        return outcome
    host = _host(event)
    executable, path = _text(event, "process.executable"), _text(event, "process.exec_file.path")
    account = _text(event, "process.user")
    for value in (host, executable, path, account):
        if isinstance(value, Missing):
            return value
    key = {"executable": executable, "exec_file_path": path}
    return [
        _key(spec, _scope("host", host=host), key),
        _key(spec, _scope("account", account=account), key),
    ]


def _exec_pair(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    host, executable = _host(event), _text(event, "process.executable")
    ppid = event.get("process.ppid")
    for value in (host, executable):
        if isinstance(value, Missing):
            return value
    if ppid is None:
        return Missing("process.ppid is absent", ("process.ppid",))
    if isinstance(ppid, bool) or not isinstance(ppid, int) or ppid < 0:
        return Missing("process.ppid is not a process id", ("process.ppid",))
    boot, serial = boot_of(event), exec_serial(event)
    parent = parent_at(context.pid_table, event.host, ppid, event.ts.timestamp(), boot, serial)
    if parent is None or boots_conflict(boot, parent[4]):
        return Pending(event.host, boot, ppid, event.ts, event.id, executable, serial)
    return [exec_pair_key(spec, host, parent[1], executable)]


def exec_pair_key(spec: BaselineSpec, host: str, parent_executable: str, child_executable: str) -> BaselineKey:
    """The exec-pair key under `spec`'s id and key version; a Pending resolved later builds the same key."""
    return _key(spec, _scope("host", host=host.strip().lower()), {
        "parent_executable": parent_executable, "child_executable": child_executable,
    })


# A key is stored once per scope and bucket, so its size is bounded: the masked shape keeps at most this many
# leading tokens and characters, and the rest is kept as its token count and a digest of its masked tokens.
ARGV_SHAPE_MAX_TOKENS = 64
ARGV_SHAPE_MAX_CHARS = 2048

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


def argv_shape(argv: list[str]) -> dict[str, Any]:
    """`argv_shape`: the masked leading tokens within the size bound; `argv_overflow` (present only when the
    bound was hit): how many masked tokens did not fit and the sha256 of their canonical JSON, so two commands
    that differ only past the bound still get different keys and the truncation is visible in the key."""
    masked = [mask_argv_token(token) for token in argv]
    kept, size = 0, 0
    for token in masked:
        if kept == ARGV_SHAPE_MAX_TOKENS or size + len(token) > ARGV_SHAPE_MAX_CHARS:
            break
        kept, size = kept + 1, size + len(token)
    shape: dict[str, Any] = {"argv_shape": masked[:kept]}
    if kept < len(masked):
        rest = masked[kept:]
        shape["argv_overflow"] = {"tokens": len(rest), "sha256": _sha256(canonical_json(rest))}
    return shape


def _cmd_shape(event: TypedEvent, _context: KeyContext, spec: BaselineSpec) -> KeyResult:
    host, executable = _host(event), _text(event, "process.executable")
    for value in (host, executable):
        if isinstance(value, Missing):
            return value
    argv = event.get("process.argv")
    if event.get("process.argv_complete") is False:
        return Missing("the argument vector is incomplete", ("process.argv",))
    if not isinstance(argv, list) or not argv or not all(isinstance(token, str) for token in argv):
        return Missing("process.argv is not a non-empty list of strings", ("process.argv",))
    return [_key(spec, _scope("host", host=host), {"executable": executable, **argv_shape(argv)})]


def _external_unicast(address: IPAddress, context: KeyContext) -> bool:
    """An address outside the site that names one remote host (not multicast, broadcast or unspecified)."""
    return not (context.is_internal(address) or address.is_multicast or address.is_unspecified
                or address.is_reserved)


def _question_names(event: TypedEvent) -> list[str] | Missing:
    """Every question name of a DNS record, canonical and distinct; a malformed list or name is Missing,
    never skipped."""
    names = event.get("dns.question.names")
    if names is not None:
        field_name = "dns.question.names"
        if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
            return Missing("dns.question.names is not a list of names", (field_name,))
    else:
        field_name = "dns.question.name"
        name = event.get(field_name)
        if name is None or name == "":
            return Missing("no DNS question name", ("dns.question.names", "dns.question.name"))
        if not isinstance(name, str):
            return Missing("dns.question.name is not a single string", (field_name,))
        names = [name]
    try:
        found = sorted({canonical for canonical in (_dns_name(value) for value in names) if canonical})
    except ValueError as error:
        return Missing(str(error), (field_name,))
    if not found:
        return Missing("no DNS question name", ("dns.question.names", "dns.question.name"))
    return found


def _dns_destination(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    record_role = dns_role(event)
    if record_role is None:
        return NotApplicable(f"DNS record role {event.get('dns.type')} is neither a question nor an answer")
    if (record_role == "answer" and event.get("dns.question.names") is None
            and event.get("dns.question.name") is None):
        return NotApplicable("an answer resource record without its question; the query record carries it")
    # The client is the endpoint not on a DNS service port, whatever the record's orientation (a sensor may write an
    # answer in its flow's orientation, client first); a question whose ports do not tell is read as sent, source to
    # destination, and an answer whose ports do not tell is Missing.
    side = dns_server_side(event, record_role)
    if side is None:
        return Missing("the DNS ports do not tell the client from the server of an answer (neither or both on a DNS "
                       "port, or a port not typed)", ("source.port", "destination.port"))
    client_field, resolver_field = (("source.ip", "destination.ip") if side == "destination"
                                    else ("destination.ip", "source.ip"))
    client = _ip(event, client_field)
    if not isinstance(client, Missing) and not context.is_internal(client):
        return NotApplicable("the DNS client is outside the site")
    resolver = _ip(event, resolver_field)
    names = _question_names(event)
    for value in (client, resolver, names):
        if isinstance(value, Missing):
            return value
    domains = sorted({domain for domain in (_registrable(name) for name in names) if domain})
    if not domains:
        return NotApplicable("the question names an address or the root, not a domain")
    # A lookup's destination is the name asked, never the resolver that answered it.
    scope = _scope("internal_ip", address=str(client))
    keys = _unique([_key(spec, scope, {"kind": "registered_domain", "registered_domain": domain})
                    for domain in domains])
    flow = _flow_identity(event)
    dns_id = event.get("dns.id")
    if isinstance(dns_id, (bool, list, dict)):
        dns_id = None
    elif dns_id is not None:
        dns_id = str(dns_id)
    token = None if flow is None else _sha256(canonical_json(["dns", flow, names, dns_id]))
    return _with_token(keys, token)


def _destination(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    if event.family == "dns_query":
        return _dns_destination(event, context, spec)
    source, destination = _ip(event, "source.ip"), _ip(event, "destination.ip")
    if not isinstance(source, Missing) and not context.is_internal(source):
        return NotApplicable("the source is outside the site (inbound or transit traffic)")
    if not isinstance(destination, Missing) and not _external_unicast(destination, context):
        return NotApplicable("the destination is not an external unicast address (east-west or local)")
    for value in (source, destination):
        if isinstance(value, Missing):
            return value
    sni_value = event.get("tls.client.server_name")
    sni = None
    if sni_value is not None:
        if not isinstance(sni_value, str):
            return Missing("tls.client.server_name is not a single string", ("tls.client.server_name",))
        try:
            sni = _dns_name(sni_value)
        except ValueError as error:
            return Missing(str(error), ("tls.client.server_name",))
    scope = _scope("internal_ip", address=str(source))
    keys = [
        _key(spec, scope, {"kind": "dest_ip", "dest_ip": str(destination)}),
        _key(spec, scope, {"kind": "dest_network", "dest_network": _network(destination)}),
    ]
    if sni is not None and sni != ".":
        keys.append(_key(spec, scope, {"kind": "sni", "sni": sni}))
        if (domain := _registrable(sni)) is not None:
            keys.append(_key(spec, scope, {"kind": "registered_domain", "registered_domain": domain}))
    flow = _flow_identity(event)
    return _with_token(_unique(keys), None if flow is None else _sha256(canonical_json(["flow", flow])))


def _uid(event: TypedEvent) -> int | Missing:
    value = event.get("process.uid")
    if value is None or value == "":
        return Missing("process.uid is absent", ("process.uid",))
    if isinstance(value, bool):
        return Missing("process.uid is not a user id", ("process.uid",))
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    # 4294967295 is the kernel's unset id, never a real account
    if not isinstance(value, int) or not 0 <= value < 4294967295:
        return Missing("process.uid is not a user id", ("process.uid",))
    return value


def _service_rate(event: TypedEvent, context: KeyContext, spec: BaselineSpec) -> KeyResult:
    account = _text(event, "process.user")
    raw_uid = event.get("process.uid")
    uid = _uid(event)
    if account == "root" or uid == 0:
        return NotApplicable("root is not a service account")
    low, high = context.system_uid_range
    if isinstance(uid, int) and not low <= uid <= high and account not in context.service_accounts:
        return NotApplicable(f"uid {uid} is outside the system range and the account is not configured")
    host = _host(event)
    for value in (host, account):
        if isinstance(value, Missing):
            return value
    if isinstance(uid, Missing) and not (raw_uid is None and account in context.service_accounts):
        # an absent uid is decided by a configured name; a malformed one is never trusted
        return uid
    return [_key(spec, _scope("host_account", host=host, account=account), {})]


_FLOW_IDS = ("suricata.flow_id", "network.community_id")

BASELINE_SPECS = (
    BaselineSpec(
        id="bl.ssh_tuple", version="1", key_version="1", families=("auth",),
        datasets=("systemd.journal",), scope="site", measure="presence", bucket="day",
        required_fields={"auth": ("auth.service", "source.ip", "user.name")},
        optional_fields={"auth": ()},
        _extract=_ssh_tuple,
    ),
    BaselineSpec(
        id="bl.exec_path", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope=("host", "account"), measure="prevalence", bucket="day",
        required_fields={
            "process_exec": ("process.executable", "process.exec_file.path", "process.user"),
        },
        optional_fields={"process_exec": ()},
        _extract=_exec_path,
    ),
    BaselineSpec(
        id="bl.exec_pair", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host", measure="prevalence", bucket="day",
        required_fields={"process_exec": ("process.executable", "process.ppid")},
        optional_fields={"process_exec": ("host.boot.id",)},
        _extract=_exec_pair,
    ),
    BaselineSpec(
        id="bl.cmd_shape", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host", measure="prevalence", bucket="day",
        required_fields={"process_exec": ("process.executable", "process.argv")},
        optional_fields={"process_exec": ("process.argv_complete",)},
        _extract=_cmd_shape,
    ),
    BaselineSpec(
        id="bl.ext_dest", version="3", key_version="3",
        families=("net_flow", "dns_query", "tls_session", "net_session"),
        datasets=(
            "suricata.eve.flow", "suricata.eve.netflow", "suricata.eve.dns", "suricata.eve.tls",
            "arkime.session",
        ),
        scope="internal_ip", measure="prevalence", bucket="day",
        required_fields={
            "net_flow": ("source.ip", "destination.ip"),
            "dns_query": ("source.ip", "destination.ip", ("dns.question.names", "dns.question.name")),
            "tls_session": ("source.ip", "destination.ip"),
            "net_session": ("source.ip", "destination.ip"),
        },
        optional_fields={
            "net_flow": (*_FLOW_IDS,),
            "dns_query": ("dns.type", "source.port", "destination.port", *_FLOW_IDS),
            "tls_session": ("tls.client.server_name", *_FLOW_IDS),
            "net_session": ("tls.client.server_name", *_FLOW_IDS),
        },
        _extract=_destination,
        requires_configured_networks=True,
    ),
    BaselineSpec(
        id="bl.svc_exec_rate", version="1", key_version="1", families=("process_exec",),
        datasets=("linux.audit",), scope="host_account", measure="rate", bucket="hour",
        # A configured account name decides one without a uid; when present, uid is still projected and typed.
        required_fields={"process_exec": ("process.user",)},
        optional_fields={"process_exec": ("process.uid",)},
        _extract=_service_rate,
    ),
)

SPEC_BY_ID = {spec.id: spec for spec in BASELINE_SPECS}
