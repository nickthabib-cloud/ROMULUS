"""The site's internal-network definition: which addresses belong to the site and which are outside it.

Many mission networks use public address space internally, and partner or VPN networks may use RFC 1918
space, so "internal" is a per-site setting (`ROMULUS_INTERNAL_NETWORKS`, with carve-outs in
`ROMULUS_EXTERNAL_NETWORKS`). Unset, the definition is the default list of RFC 1918 and reserved ranges and is
labelled as such: rules whose negative depends on direction then state that the direction was assumed.

One definition is installed per hunt, before the sweep, and every address test in the detectors reads it
(`romulus.detect.host.is_internal`, `romulus.detect.correlation.external`). Lookups take the most specific
matching prefix, so a carve-out beats the broader internal range it sits in. Loopback and link-local ranges
are always internal: they never leave the host or the segment.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable, Iterable
from functools import lru_cache
from typing import Literal

type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_INTERNAL = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")
ALWAYS_INTERNAL = ("127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10")
DEFAULT_LABEL = "default (RFC 1918 and reserved ranges)"
INTERNAL_SETTING = "ROMULUS_INTERNAL_NETWORKS"
EXTERNAL_SETTING = "ROMULUS_EXTERNAL_NETWORKS"
# The coverage reason for a record a rule skipped, or judged, by direction alone under the default definition.
DIRECTION_ASSUMED_REASON = ("internal networks not configured for this site; direction assumed from RFC 1918 "
                            "defaults")
RECORD_SCHEMA = "site-networks@1"
LOOKUP_CACHE = 65_536            # distinct addresses whose answer each definition keeps


def parse_network(text: str, setting: str) -> IPNetwork:
    """One CIDR (or a single address, as a host route). Host bits set after the prefix are refused: such a value
    is usually a typo, and guessing the intended network could widen or narrow the site."""
    value = text.strip()
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ValueError(f"{setting}: {value!r} is not a CIDR network ({error})") from None


def parse_networks(values: Iterable[str], setting: str) -> tuple[IPNetwork, ...]:
    return tuple(parse_network(value, setting) for value in values)


def _canonical(networks: Iterable[IPNetwork]) -> tuple[IPNetwork, ...]:
    return tuple(sorted(set(networks), key=lambda n: (n.version, int(n.network_address), n.prefixlen)))


class SiteNetworks:
    """An immutable internal-network definition with a source label and a digest.

    `internal` holds the ranges the definition names (the configured list, or the default list); `external`
    the carve-outs. The effective internal set also holds `ALWAYS_INTERNAL`."""

    __slots__ = ("_lookup", "_tables", "digest", "external", "internal", "source")

    def __init__(self, source: Literal["configured", "default"], internal: Iterable[IPNetwork],
                 external: Iterable[IPNetwork] = ()):
        if source not in ("configured", "default"):
            raise ValueError(f"unknown internal-network source {source!r}")
        internal, external = _canonical(internal), _canonical(external)
        always = parse_networks(ALWAYS_INTERNAL, "always-internal ranges")
        effective = _canonical((*internal, *always))
        for carve in external:
            if any(carve.version == n.version and carve.overlaps(n) for n in always):
                raise ValueError(f"{EXTERNAL_SETTING}: {carve} overlaps a loopback or link-local range, which is "
                                 "always internal")
            if not any(carve.version == n.version and carve.subnet_of(n) for n in effective):
                raise ValueError(f"{EXTERNAL_SETTING}: {carve} is not inside any internal network; a carve-out "
                                 "names part of an internal range that must be treated as outside")
            if carve in effective:
                raise ValueError(f"{EXTERNAL_SETTING}: {carve} is also listed as an internal network")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "internal", internal)
        object.__setattr__(self, "external", external)
        material = {"schema": RECORD_SCHEMA, "source": source, "internal": [str(n) for n in internal],
                    "external": [str(n) for n in external], "always_internal": list(ALWAYS_INTERNAL)}
        object.__setattr__(self, "digest", hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        # Per address family: (prefix length, {network bits: internal?}), longest prefix first.
        tables: dict[int, list[tuple[int, dict[int, bool]]]] = {4: [], 6: []}
        by_length: dict[tuple[int, int], dict[int, bool]] = {}
        for verdict, networks in ((True, effective), (False, external)):
            for net in networks:
                shift = net.max_prefixlen - net.prefixlen
                by_length.setdefault((net.version, net.prefixlen), {})[int(net.network_address) >> shift] = verdict
        for (version, length), entries in sorted(by_length.items(), key=lambda item: -item[0][1]):
            tables[version].append((length, entries))
        object.__setattr__(self, "_tables", tables)
        object.__setattr__(self, "_lookup", lru_cache(maxsize=LOOKUP_CACHE)(self._decide))

    def __setattr__(self, name, value):
        raise AttributeError("SiteNetworks is immutable")

    def __eq__(self, other) -> bool:
        return isinstance(other, SiteNetworks) and other.digest == self.digest

    def __hash__(self) -> int:
        return hash(self.digest)

    def __repr__(self) -> str:
        return f"SiteNetworks({self.summary()!r}, digest={self.digest[:12]})"

    # -- construction ------------------------------------------------------------------------------
    @classmethod
    def default(cls, external: Iterable[IPNetwork] = ()) -> SiteNetworks:
        return cls("default", parse_networks(DEFAULT_INTERNAL, "default ranges"), external)

    @classmethod
    def from_lists(cls, internal: Iterable[str] | None, external: Iterable[str] | None = None) -> SiteNetworks:
        """A configured definition when any internal network is given; otherwise the default, with any
        carve-outs applied to it (carve-outs alone do not say where the site is)."""
        nets = parse_networks(internal or (), INTERNAL_SETTING)
        carve = parse_networks(external or (), EXTERNAL_SETTING)
        return cls("configured", nets, carve) if nets else cls.default(carve)

    @classmethod
    def from_settings(cls, settings) -> SiteNetworks:
        return cls.from_lists(settings.internal_networks, settings.external_networks)

    @classmethod
    def from_record(cls, record: dict | None) -> SiteNetworks:
        """The definition a hunt manifest recorded. A hunt recorded before the setting existed used the default."""
        if record is None:
            return cls.default()
        definition = cls(record["source"], parse_networks(record.get("internal") or (), INTERNAL_SETTING),
                         parse_networks(record.get("external") or (), EXTERNAL_SETTING))
        if record.get("digest") != definition.digest:
            raise ValueError("the recorded internal-network definition does not match its digest")
        return definition

    # -- lookups -----------------------------------------------------------------------------------
    def _decide(self, ip: IPAddress) -> bool:
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped                         # ::ffff:a.b.c.d names the IPv4 host a.b.c.d
        value = int(ip)
        bits = ip.max_prefixlen
        for length, entries in self._tables[ip.version]:
            verdict = entries.get(value >> (bits - length))
            if verdict is not None:
                return verdict
        return False

    def is_internal(self, ip: IPAddress) -> bool:
        """Whether the address belongs to the site. The most specific matching range decides."""
        return self._lookup(ip)

    def cache_info(self):
        return self._lookup.cache_info()

    # -- description and provenance ----------------------------------------------------------------
    @property
    def configured(self) -> bool:
        return self.source == "configured"

    @property
    def label(self) -> str:
        return "configured" if self.configured else DEFAULT_LABEL

    def summary(self) -> str:
        carve = len(self.external)
        carved = f"{carve} carve-out{'s' if carve != 1 else ''}"
        if self.configured:
            ranges = len(self.internal)
            return f"Internal networks: configured ({ranges} range{'s' if ranges != 1 else ''}, {carved})"
        return f"Internal networks: {DEFAULT_LABEL}{', ' + carved if carve else ''}; not configured for this site"

    def record(self) -> dict:
        """What the hunt manifest records: source label, ranges, digest and the one-line summary."""
        return {"schema": RECORD_SCHEMA, "source": self.source, "label": self.label,
                "internal": [str(n) for n in self.internal], "external": [str(n) for n in self.external],
                "always_internal": list(ALWAYS_INTERNAL), "digest": self.digest, "summary": self.summary()}


def recorded_view(record: dict | None) -> dict:
    """A hunt's recorded definition for a report or page: the record (the default for a hunt recorded before the
    setting existed) with its one-line summary. A record that does not match its digest is shown as such."""
    try:
        return SiteNetworks.from_record(record).record()
    except (KeyError, TypeError, ValueError) as error:
        return {"source": "unreadable", "digest": (record or {}).get("digest"),
                "summary": f"Internal networks: the hunt's recorded definition is unreadable ({error})"}


# ---- the installed definition ----------------------------------------------------------------------------

_installed: SiteNetworks = SiteNetworks.default()
_on_install: list[Callable[[], None]] = []


def current() -> SiteNetworks:
    return _installed


def install(definition: SiteNetworks) -> None:
    """Make `definition` the one every address test reads, and drop every cache derived from the previous one."""
    global _installed
    _installed = definition
    for reset in _on_install:
        reset()


def on_install(reset: Callable[[], None]) -> Callable[[], None]:
    """Register a cache reset to run whenever a definition is installed."""
    _on_install.append(reset)
    return reset


def assume_direction(playbook) -> None:
    """Count one record a rule skipped, or judged, by direction alone. Under the default definition the
    direction is an assumption, so the record cannot support a complete negative; under a configured one the
    direction is the site's own and the count stays zero."""
    if not _installed.configured:
        playbook.direction_assumed += 1
