"""Independent protocol sets on one Arkime net_session, never transaction fan-out.

The official parser field registrations (capture/parsers/{smb,krb5,ldap,tls,http}.c,
https://github.com/arkime/arkime/tree/main/capture/parsers) define stored names.
`smb.fn` is a search expression for stored `smb.filename`. SMB host is the NTLM
workstation, not the share server. TLS SNI is stored in shared `http.host`; only
a TLS-only session permits attributing those values to SNI. HTTP Content-Length
headers are declarations, not observed body sizes, and header-name/value sets
are not paired. Configured safe request headers retain independent list values.
"""
from __future__ import annotations

import copy
import re

from romulus.evidence.typed import fv
from romulus.evidence.zeek_credentials import strip_uri_userinfo

ARKIME_NORMALIZER = "arkime@1"
ARKIME_PROTOCOL_FIELDS = (
    ("smb.name", "smb.filename"), ("ntlm.username", "smb.user"), ("ntlm.hostname", "smb.host"),
    ("ntlm.domain", "smb.domain"), ("smb.version", "smb.version"),
    ("kerberos.client_name", "krb5.cname"), ("kerberos.service", "krb5.sname"),
    ("kerberos.realms", "krb5.realm"),
    ("ldap.bind_type", "ldap.authtype"), ("ldap.objects", "ldap.bindname"),
    ("http.request.referrer", "http.request-referer"), ("http.request.origin", "http.request-origin"),
)
AGGREGATE_CAVEAT = "Arkime protocol values are unpaired session sets, not ordered or counted transactions"


def _read(source, path, bad):
    cur = source
    for name in path.split("."):
        if cur is None:
            return None
        if not isinstance(cur, dict):
            bad.append(path)
            return None
        cur = cur.get(name)
    if cur is None or cur == []:
        return None
    if isinstance(cur, str):
        return [cur]
    if isinstance(cur, list) and all(isinstance(v, str) for v in cur):
        return sorted(set(cur))
    bad.append(path)
    return None


def arkime_protocol_fields(source: dict, nid: str, bad: list[str], caveats: list[str]) -> dict:
    fields = {}
    for typed, path in ARKIME_PROTOCOL_FIELDS:
        values = _read(source, path, bad)
        if path == "smb.filename" and values is None and path not in bad:
            path = "smb.fn"
            values = _read(source, path, bad)
        if values:
            if typed in ("http.request.referrer", "http.request.origin"):
                clean = []
                for value in values:
                    text, removed, password = strip_uri_userinfo(value)
                    if removed:
                        certainty = "present" if password else "unknown"
                        fields["auth.cleartext_credentials_" + certainty] = fv(True, f"{nid}:{path}#" + certainty)
                    clean.append(text)
                values = sorted(set(clean))
            fields[typed] = fv(values, f"{nid}:{path}")
    shares = _read(source, "smb.share", bad)
    if shares:
        paths, hosts, names = set(), set(), set()
        for share in shares:
            body = re.sub(r"\\+", lambda _m: "\\", share.lstrip("\\"))
            path = ("\\\\" if share.startswith("\\") else "") + body
            paths.add(path)
            if path.startswith("\\\\"):
                host, _, rest = path[2:].partition("\\")
                if host:
                    hosts.add(host)
                if rest:
                    names.add(rest.partition("\\")[0])
            else:
                names.add(path)
        fields["smb.path"] = fv(sorted(paths), f"{nid}:smb.share")
        if hosts:
            fields["smb.host"] = fv(sorted(hosts), f"{nid}:smb.share#derived:unc-host")
        if names:
            fields["smb.share"] = fv(sorted(names), f"{nid}:smb.share#derived:unc-share")
    protocols = source.get("protocol", [])
    protocols = {p.casefold() for p in protocols if isinstance(p, str)} if isinstance(protocols, list) else set()
    if "tls" in protocols:
        hosts = _read(source, "http.host", bad)
        if hosts and not protocols.intersection({"http", "http2"}):
            fields["tls.client.server_name"] = fv(hosts, f"{nid}:http.host#derived:tls-only-SNI")
        elif hosts:
            caveats.append("Arkime shared HTTP host/SNI values are ambiguous in a mixed HTTP/TLS session")
    http = source.get("http")
    if isinstance(http, dict):
        if "request-content-length" in http or "response-content-length" in http:
            caveats.append("Arkime declared Content-Length headers do not establish observed HTTP body size")
        if any(http.get(key) for key in _credential_header_keys(http)):
            fields["auth.cleartext_credentials_unknown"] = fv(True, f"{nid}:http#credential-header")
        if "requestHeaderValue" in http or "responseHeaderValue" in http:
            caveats.append("Arkime header values have no persisted ordered name pairing; raw header values are not typed")
    if fields:
        caveats.append(AGGREGATE_CAVEAT)
    return fields


_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})


def _credential_header_keys(http):
    keys = {direction + "-" + name for direction in ("request", "response") for name in _CREDENTIAL_HEADERS}
    for direction in ("request", "response"):
        names = http.get(direction + "Header", [])
        if isinstance(names, str):
            names = [names]
        if isinstance(names, list) and any(isinstance(name, str) and name.casefold() in _CREDENTIAL_HEADERS for name in names):
            # HeaderField is NODB; there is no trustworthy persisted position pairing.
            keys.add(direction + "HeaderValue")
    return keys


def scrub_arkime_source(source: dict) -> dict:
    """Mask known credential headers and URI userinfo only on recognized SPI sessions.

    Unpaired header values are masked together when a credential header is present;
    names and unrelated stored fields remain. Unknown layouts are not interpreted.
    """
    if "firstPacket" not in source or "lastPacket" not in source or not isinstance(source.get("source"), dict):
        return source
    http = source.get("http")
    if not isinstance(http, dict):
        return source
    replacements = {}
    for key in _credential_header_keys(http):
        value = http.get(key)
        if value is not None and value != [] and value != "":
            replacement = ["<redacted>" for _ in value] if isinstance(value, list) else "<redacted>"
            if value != replacement:
                replacements[key] = replacement
    for key in ("request-referer", "request-origin"):
        value = http.get(key)
        values = [value] if isinstance(value, str) else value
        if isinstance(values, list) and all(isinstance(item, str) for item in values):
            clean = [strip_uri_userinfo(item)[0] for item in values]
            replacement = clean[0] if isinstance(value, str) else clean
            if replacement != value:
                replacements[key] = replacement
    if not replacements:
        return source
    result = copy.deepcopy(source)
    result["http"].update(replacements)
    return result
