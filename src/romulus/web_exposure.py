"""How the web UI is exposed: the bind address, built-in TLS, the plain-HTTP rule, trusted proxies and the session
cookie's Secure flag. Shared by `romulus web`, the web application and doctor, so all judge a configuration alike."""
from __future__ import annotations

import ipaddress

from romulus.config import Settings

PLAINTEXT_SWITCH = "ROMULUS_WEB_ALLOW_PLAINTEXT=1"


def bind_address(s: Settings) -> tuple[str, int]:
    """(host, port) of ROMULUS_WEB_BIND; an IPv6 host may be written in brackets ([::1]:8443)."""
    host, _, port = s.web_bind.rpartition(":")
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        number = int(port)
    except ValueError:
        raise ValueError(f"ROMULUS_WEB_BIND must be host:port, not {s.web_bind!r}") from None
    if not 0 < number < 65536:
        raise ValueError(f"ROMULUS_WEB_BIND port must be 1-65535, not {port}")
    return host, number


def is_loopback(host: str) -> bool:
    """True only for an address no other machine can reach. An empty host or a wildcard (0.0.0.0, ::) is not."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def tls_half_configured(s: Settings) -> bool:
    return bool(s.web_tls_cert) != bool(s.web_tls_key)


def plaintext_state(s: Settings) -> str:
    """'tls' (built-in TLS), 'loopback' (plain HTTP reachable only from this machine), 'allowed' (plain HTTP on the
    network under ROMULUS_WEB_ALLOW_PLAINTEXT) or 'refused' (plain HTTP on the network without it)."""
    if s.web_tls_enabled:
        return "tls"
    if is_loopback(bind_address(s)[0]):
        return "loopback"
    return "allowed" if s.web_allow_plaintext else "refused"


def refusal(s: Settings) -> str | None:
    """Why the server must not start with this configuration, or None."""
    if tls_half_configured(s):
        return "set both ROMULUS_WEB_TLS_CERT and ROMULUS_WEB_TLS_KEY for built-in TLS, or neither"
    try:
        trusted_proxies(s)
        state = plaintext_state(s)
    except ValueError as exc:
        return str(exc)
    if state == "refused":
        host = bind_address(s)[0] or "every interface"
        return (f"refusing to serve plain HTTP on {host}: session cookies and passwords would cross the network "
                f"unencrypted. Set ROMULUS_WEB_TLS_CERT and ROMULUS_WEB_TLS_KEY for built-in TLS, bind "
                f"ROMULUS_WEB_BIND to 127.0.0.1 behind a TLS reverse proxy, or set {PLAINTEXT_SWITCH} to accept "
                f"plain HTTP on an isolated lab network.")
    return None


def trusted_proxies(s: Settings) -> list[str]:
    """Addresses or networks (CIDR) of the reverse proxies whose forwarded headers are trusted. A wildcard is refused:
    any client could then choose the address the login throttle and the audit log see."""
    out = []
    for item in (part.strip() for part in s.web_trusted_proxies.split(",")):
        if not item:
            continue
        if item == "*":
            raise ValueError("ROMULUS_WEB_TRUSTED_PROXIES must list proxy addresses, not '*'")
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"ROMULUS_WEB_TRUSTED_PROXIES entry {item!r} is not an IP address or network") from None
        if network.prefixlen == 0:
            raise ValueError(f"ROMULUS_WEB_TRUSTED_PROXIES entry {item!r} trusts every address")
        out.append(item)
    return out


def uvicorn_options(s: Settings) -> dict:
    """Keyword arguments for uvicorn.run. Forwarded headers are read only from the configured proxies; with none
    configured the connection's own address is the client."""
    host, port = bind_address(s)
    proxies = trusted_proxies(s)
    options = {"host": host, "port": port, "ssl_certfile": s.web_tls_cert or None,
               "ssl_keyfile": s.web_tls_key or None, "proxy_headers": bool(proxies)}
    if proxies:
        options["forwarded_allow_ips"] = proxies
    return options


def cookie_secure(s: Settings, scheme: str) -> bool:
    """Mark the session cookie Secure under built-in TLS, under ROMULUS_COOKIE_SECURE=1, or when the request arrived
    over HTTPS (as a trusted proxy reports it)."""
    return s.web_tls_enabled or s.web_cookie_secure or scheme == "https"
