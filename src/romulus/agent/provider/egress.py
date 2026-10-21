"""Classify a model endpoint as local or remote, and decide whether telemetry excerpts may be sent to it.

An endpoint is local when its host is loopback, RFC 1918 or IPv6 unique-local, or is listed in
MODEL_LOCAL_HOSTS (a hostname, an address, or a CIDR network no wider than /8, or /16 for IPv6). A hostname
counts as local only when every address it resolves to is local; a name that does not resolve is remote. The
name classified is the ASCII form the client connects to. Every other endpoint is remote and
is refused unless the bootstrap configuration sets ROMULUS_MODEL_EGRESS=lab-public-data.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

import httpx

EGRESS_SWITCH_VALUE = "lab-public-data"

LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
))

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


@dataclass(frozen=True)
class EgressDecision:
    host: str
    scheme: str
    egress: str                 # local | remote
    basis: str                  # why it was classified so
    addresses: tuple[str, ...]
    allowed: bool               # may telemetry excerpts be sent to this endpoint
    refusal: str = ""           # the reason when not allowed

    def as_dict(self) -> dict:
        return {"host": self.host, "scheme": self.scheme, "egress": self.egress, "basis": self.basis,
                "addresses": list(self.addresses), "allowed": self.allowed, "refusal": self.refusal}


class EndpointError(ValueError):
    """The configured endpoint URL is unusable (bad scheme, credentials in the URL, no host)."""


def parse_endpoint(base_url: str) -> httpx.URL:
    try:
        url = httpx.URL(base_url.strip())
    except (httpx.InvalidURL, TypeError) as exc:
        raise EndpointError(f"AGENT_BASE_URL is not a valid URL: {exc}") from exc
    if url.scheme not in ("http", "https"):
        raise EndpointError("AGENT_BASE_URL must use http or https")
    if not url.host:
        raise EndpointError("AGENT_BASE_URL has no host")
    if url.userinfo:
        # credentials embedded in the URL would end up in logs and manifests; use AGENT_API_KEY
        raise EndpointError("AGENT_BASE_URL must not carry credentials; put the key in AGENT_API_KEY")
    return url


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


MIN_LISTED_PREFIX = {4: 8, 6: 16}     # a wider MODEL_LOCAL_HOSTS network would make public space "local"


def _listed(local_hosts: list[str]) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    names: set[str] = set()
    networks = []
    for entry in local_hosts:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            names.add(entry)
            continue
        if network.prefixlen < MIN_LISTED_PREFIX[network.version]:
            raise EndpointError(f"MODEL_LOCAL_HOSTS entry {entry} is too wide: list your model servers' own "
                                f"networks (at most /{MIN_LISTED_PREFIX[network.version]})")
        networks.append(network)
    return names, networks


def classify(base_url: str, local_hosts: list[str], egress_switch: str,
             resolver: Resolver = system_resolver) -> EgressDecision:
    url = parse_endpoint(base_url)
    # classify exactly the name the client will connect to (its ASCII/IDNA form)
    host = url.raw_host.decode("ascii").lower()
    if host.endswith("."):
        raise EndpointError("AGENT_BASE_URL host must not end with a dot")
    names, listed_networks = _listed(local_hosts)

    def where(address) -> str | None:
        if any(address.version == net.version and address in net for net in listed_networks):
            return "listed"
        if any(address.version == net.version and address in net for net in LOCAL_NETWORKS):
            return "private"
        return None

    if host in names:
        egress, basis, addresses = "local", "the name is listed in MODEL_LOCAL_HOSTS", ()
    elif host == "localhost":
        egress, basis, addresses = "local", "localhost", ()
    else:
        literal = _address(host)
        if literal is not None:
            addresses = (str(literal),)
            kind = where(literal)
            egress = "local" if kind else "remote"
            basis = {"listed": "the address is in MODEL_LOCAL_HOSTS",
                     "private": "the address is loopback or private"}.get(kind or "",
                                                                             "the address is not loopback, private or listed")
        else:
            basis = "name resolved to no address; treated as remote"
            try:
                resolved = resolver(host)
            except OSError as exc:
                resolved, basis = [], f"name did not resolve ({exc.__class__.__name__}); treated as remote"
            except ValueError as exc:      # includes UnicodeError: a label the resolver cannot encode
                raise EndpointError(f"AGENT_BASE_URL host {host!r} is not a valid name: {exc}") from None
            addresses = tuple(resolved)
            kinds = [where(a) if a is not None else None for a in (_address(r) for r in resolved)]
            if resolved and all(kinds):
                egress = "local"
                basis = ("every resolved address is loopback or private" if set(kinds) == {"private"}
                         else "every resolved address is loopback, private or in MODEL_LOCAL_HOSTS")
            else:
                egress = "remote"
                if resolved:
                    basis = "resolves to an address that is not loopback, private or listed"
    if egress == "local":
        return EgressDecision(host, url.scheme, egress, basis, addresses, True)
    if egress_switch != EGRESS_SWITCH_VALUE:
        return EgressDecision(host, url.scheme, egress, basis, addresses, False,
                              f"{host} is a remote endpoint ({basis}); telemetry may be sent to it only when the "
                              f"bootstrap .env sets ROMULUS_MODEL_EGRESS={EGRESS_SWITCH_VALUE} (public data only), "
                              "or when it is the team's own server listed in MODEL_LOCAL_HOSTS")
    if url.scheme != "https":
        return EgressDecision(host, url.scheme, egress, basis, addresses, False,
                              f"{host} is a remote endpoint over plain HTTP; a remote endpoint must use https")
    return EgressDecision(host, url.scheme, egress, basis, addresses, True)
