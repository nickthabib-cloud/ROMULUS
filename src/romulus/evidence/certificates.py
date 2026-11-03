"""The certificate contract every network normalizer shares: the typed fields for the certificates one record shows.

A certificate is a dict with these keys: subject_cn, subject_on, issuer_cn, issuer_on, alt_names (list[str]);
subject_dn, issuer_dn (str or None); not_before, not_after (ISO-8601 UTC or None); valid_days (int or None); sha1,
serial (lowercase hex or None). `certificate_fields` adds names_compared, self_issued and issues_other and sets the
server-certificate fields (see the contract in romulus.evidence.normalize).
"""
from __future__ import annotations

import json
import re

from romulus.evidence.typed import fv

# One-line distinguished names ("C=US, O=Example, CN=host" or Zeek's "CN=host,O=Example,C=US"): a comma followed by an
# attribute type and "=" starts the next attribute, so a comma inside a value ("O=Acme, Inc.") does not split.
RDN_SPLIT = re.compile(r",\s*(?=[A-Za-z][A-Za-z0-9.-]*=)")


def _absent(value) -> bool:
    return value is None or value == "" or value == [] or value == {}


def dn_parts(dn: str) -> list[tuple[str, str]]:
    """(attribute type, value) pairs of a one-line distinguished name, types uppercased."""
    parts = []
    for rdn in RDN_SPLIT.split(dn.strip()):
        key, sep, val = rdn.partition("=")
        if sep and key.strip():
            parts.append((key.strip().upper(), val.strip()))
    return parts


def name_key(cert: dict, side: str):
    """Comparable identity of a certificate's subject or issuer name: the whole distinguished name when the
    source recorded it, otherwise its CN and O values. None when nothing is recorded."""
    dn = cert.get(f"{side}_dn")
    if dn:
        parts = dn_parts(dn)
        if parts:
            return ("dn", tuple((key, val.casefold()) for key, val in parts))
    cn = tuple(sorted({v.casefold() for v in cert[f"{side}_cn"]}))
    on = tuple(sorted({v.casefold() for v in cert[f"{side}_on"]}))
    return ("cn_on", cn, on) if (cn or on) else None


def certificate_fields(certs: list[dict], origin: str, caveats: list[str]) -> dict:
    """Typed fields for the certificates one record presented: dedupe, sort, mark self-issued certificates and
    the ones that issued another presented certificate, and set the server-certificate fields only when that
    certificate is unambiguous."""
    distinct = {json.dumps(c, sort_keys=True): c for c in certs}
    certs = sorted(distinct.values(), key=lambda c: (c["sha1"] or "", json.dumps(c["subject_cn"]),
                                                     c["subject_dn"] or "", c["not_before"] or ""))
    for cert in certs:
        subject, issuer = name_key(cert, "subject"), name_key(cert, "issuer")
        cert["names_compared"] = "distinguished name" if cert["subject_dn"] and cert["issuer_dn"] else "CN and O"
        cert["self_issued"] = None if subject is None or issuer is None else subject == issuer
        cert["issues_other"] = subject is not None and any(
            other is not cert and name_key(other, "issuer") == subject for other in certs)
    f = {"tls.server.certificates": fv(certs, origin)}
    leaves = [c for c in certs if not c["issues_other"]]
    if len(leaves) == 1:
        leaf, derived = leaves[0], f"{origin}#derived:server-certificate"
        for typed, key in (("tls.server.subject_cn", "subject_cn"), ("tls.server.issuer_cn", "issuer_cn"),
                           ("tls.server.not_before", "not_before"), ("tls.server.not_after", "not_after"),
                           ("tls.server.hash_sha1", "sha1")):
            if not _absent(leaf[key]):
                f[typed] = fv(leaf[key], derived)
    else:
        caveats.append(f"{len(leaves)} presented certificates issue no other presented certificate: the server's "
                       f"own certificate is ambiguous; per-certificate values are in tls.server.certificates")
    return f
