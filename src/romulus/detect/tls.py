"""Certificates that public servers presented to internal clients.

Two shapes common in attacker infrastructure, read from the typed certificate fields the Suricata and Arkime
normalizers share (`tls.server.certificates`, contract in romulus.evidence.normalize):

- a certificate whose subject name equals its issuer name and that issues no other presented certificate (a
  self-signed server certificate, not a root CA sent along with its chain);
- a server certificate with a short validity period, or one issued shortly before (or after) the session.

What the evidence shows, and what it does not:
- The sensor saw the certificate in the server's handshake. TLS 1.3 encrypts the certificate and a resumed
  session sends none, so on those sessions this cannot be judged: such records are counted as missing, and the
  rule's negative is partial whenever they exist. Arkime puts handshake fields on the first record of a split
  session only; later records (`arkime.continuation`) are not judged.
- "Self-signed" is judged by name, not by signature: the whole distinguished name when Suricata recorded it,
  the CN and O values when only Arkime did. A certificate signed by a different key under the same name reads
  as self-issued; the claim says which names were compared.
- Validity and age are the certificate's own notBefore/notAfter against the session time. They say nothing
  about who controls the server.

"Outbound" means the session's client (source) address is inside the configured internal space and its server
(destination) address is public. Findings are grouped per (certificate, server address).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.correlation import canon_ip, external
from romulus.evidence.typed import TypedEvent

EXAMPLE_LIMIT = 20
TLS_HINT_FIELDS = ("tls.ja3", "tls.ja3s", "tls.ja4", "tls.version", "tls.server.certificates")


def outbound(e: TypedEvent) -> bool | None:
    """Internal client to public server; None when either address is absent or not an address."""
    src, dst = canon_ip(e.get("source.ip")), canon_ip(e.get("destination.ip"))
    if src is None or dst is None:
        return None
    return not external(src) and external(dst)


def is_tls_record(e: TypedEvent) -> bool:
    """A record of a TLS session: a Suricata tls event, or an Arkime session its parser identified as TLS or that
    carries handshake fields."""
    if e.family == "tls_session":
        return True
    protocols = e.get("network.protocols")
    protocols = protocols if isinstance(protocols, list) else [protocols]
    return "tls" in protocols or any(e.has(name) for name in TLS_HINT_FIELDS)


def _when(value) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _identity(cert: dict) -> str:
    if cert.get("sha1"):
        return cert["sha1"]
    return json.dumps([cert.get("subject_dn"), cert.get("subject_cn"), cert.get("subject_on"), cert.get("issuer_dn"),
                       cert.get("issuer_cn"), cert.get("issuer_on"), cert.get("not_before"), cert.get("not_after")])


def describe(cert: dict) -> str:
    def name(side: str) -> str:
        if cert.get(f"{side}_dn"):
            return f"'{cert[f'{side}_dn']}'"
        parts = [f"CN={v}" for v in cert.get(f"{side}_cn") or []] + [f"O={v}" for v in cert.get(f"{side}_on") or []]
        return f"'{', '.join(parts)}'" if parts else "(none recorded)"
    text = f"subject {name('subject')}, issuer {name('issuer')}"
    if cert.get("not_before") or cert.get("not_after"):
        text += f", valid {cert.get('not_before') or '?'} to {cert.get('not_after') or '?'}"
    if cert.get("sha1"):
        text += f", SHA-1 {cert['sha1']}"
    return text


class _CertificateRule(Playbook):
    """Shared consumption: outbound TLS records, their server certificates, coverage counting, grouping."""
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "network_observation"
    families = ("tls_session", "net_session")
    required_fields = ("source.ip", "destination.ip")
    severity, lane = "medium", "lead"

    def __init__(self):
        super().__init__()
        self._seen: set[str] = set()
        self.groups: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.info: dict[tuple, dict] = {}

    def judge(self, e: TypedEvent, cert: dict) -> list[str] | None:
        """Reasons one candidate server certificate matches: non-empty on a match, empty when it was judged and
        does not match, None when a field the judgement needs is missing."""
        raise NotImplementedError

    def consume(self, events):
        for e in self.applicable([e for e in events if e.id not in self._seen]):
            self._seen.add(e.id)               # a record read twice (split partitions) is judged once
            if not is_tls_record(e) or outbound(e) is not True:
                continue                        # judged: not an outbound TLS session, nothing to see
            if e.get("arkime.continuation") is True:
                continue                        # the first record of this Arkime session holds the handshake
            certs = e.get("tls.server.certificates")
            candidates = [c for c in certs if not c.get("issues_other")] if isinstance(certs, list) else []
            if not candidates:
                # TLS 1.3, a resumed session or a malformed certificate block: the certificate is not visible
                self.evaluated -= 1
                self.missing_required += 1
                continue
            unknown = False
            for cert in candidates:
                reasons = self.judge(e, cert)
                if reasons is None:
                    unknown = True
                elif reasons:
                    self._keep(e, cert, reasons)
            if unknown:
                self.evaluated -= 1
                self.missing_required += 1
        return []

    def _keep(self, e: TypedEvent, cert: dict, reasons: list[str]) -> None:
        key = (_identity(cert), str(e.get("destination.ip")))
        g = self.info.get(key)
        if g is None:
            g = self.info[key] = {"cert": cert, "records": 0, "sources": set(), "ports": set(), "conns": set(),
                                  "reasons": set(), "first": e.ts, "last": e.ts}
        g["records"] += 1
        g["sources"].add(str(e.get("source.ip")))
        g["ports"].add(str(e.get("destination.port")))
        g["conns"].add(str(e.get("network.community_id") or e.get("suricata.flow_id") or e.id))
        g["reasons"].update(reasons)
        g["first"], g["last"] = min(g["first"], e.ts), max(g["last"], e.ts)
        group = self.groups[key]
        if len(group) < EXAMPLE_LIMIT:
            group.append(e)
            group.sort(key=lambda event: (event.ts, event.id))
        elif (e.ts, e.id) < (group[-1].ts, group[-1].id):
            group[-1] = e                               # keep the earliest records whatever the reading order
            group.sort(key=lambda event: (event.ts, event.id))

    def summary(self, key: tuple) -> str:
        g = self.info[key]
        sources = sorted(g["sources"])
        return (f"{g['records']} record(s) of {len(g['conns'])} outbound TLS connection(s) from "
                f"{', '.join(sources[:5])}{' and others' if len(sources) > 5 else ''} to {key[1]} port(s) "
                f"{', '.join(sorted(g['ports']))} ({g['first'].isoformat()} – {g['last'].isoformat()})")

    def predicate(self, evs: list[TypedEvent]):
        return [pf(evs[0], "tls.server.certificates"), pf(evs[0], "source.ip"), pf(evs[0], "destination.ip")]


class SelfSignedCertificateOutbound(_CertificateRule):
    id = "net.tls_self_signed_certificate_outbound"
    title = "Public server presented a certificate whose subject name equals its issuer name"
    attack = ("T1573.002", "T1587.003", "T1608.003")
    benign = (("appliances, VPN concentrators and management interfaces reached over the internet with their "
               "factory certificate"), "developer and test services", "IoT devices calling home to vendor endpoints")
    next_checks = ("which process on the internal host made these connections (host sockets at the same time)",
                   ("how many internal hosts reach this server, and whether the destination is a known vendor "
                    "service"), "beaconing or long connections to the same server")
    card: ClassVar[dict] = {
        "behavior": "an internal client completed a TLS handshake in which a public server presented a "
                    "certificate whose subject name equals its issuer name and that issues no other presented "
                    "certificate",
        "telemetry": "Suricata EVE tls (tls.subject, tls.issuerdn) as tls_session, and Arkime 6.x session cert "
                     "objects (subjectCN/ON, issuerCN/ON) as net_session; both normalized into "
                     "tls.server.certificates. Present in the lab profile, but certificates are visible only on "
                     "TLS 1.2 and earlier handshakes",
        "fidelity": "direct observation of the presented certificate's names; self-signed is judged by name "
                    "equality, not by verifying the signature; says nothing about what the session carried",
        "benign_and_cost": "factory certificates on appliances and IoT vendor endpoints, test services. One "
                           "grouped finding per (certificate, server address)",
        "query_cost": "none beyond the sweep: it reads the network partitions every network rule reads",
        "next_pivot": "the internal process that opened the connection, and the destination's prevalence across "
                      "internal hosts",
        "adds": "no other rule reads server certificates; the indicator rule matches only listed fingerprints",
        "research_basis": "ATT&CK Enterprise 20.0 T1587.003 and T1608.003 (adversary-generated and installed "
                          "certificates), T1573.002; backlog BL-13. Reimplemented from the behavior; no rule "
                          "content copied",
        "retrieval": "the sweep retrieves every record of the network targets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "missing": "an outbound TLS record without a visible server certificate (TLS 1.3, resumption, malformed "
                   "block) or whose certificate has no recorded names is counted missing, so the negative is "
                   "partial",
    }

    def judge(self, e, cert):
        if cert.get("self_issued") is None:
            return None
        return ["self-issued"] if cert["self_issued"] else []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            g = self.info[key]
            cert = g["cert"]
            compared = cert.get("names_compared") or "CN and O"
            claim = (f"{self.summary(key)}: the server presented a certificate whose subject name equals its issuer "
                     f"name ({describe(cert)}), and no other certificate in the handshake names it as issuer. "
                     f"Compared by {compared}; the signature was not verified.")
            out.append(Match(self.id, claim, self.claim_type, evs, self.predicate(evs), evs[0].ts, self.severity,
                             self.lane, "high" if compared == "distinguished name" else "medium", evs[0].entities(),
                             group_key=f"{key[0]}|{key[1]}"))
        return out


class ShortLivedOrNewCertificateOutbound(_CertificateRule):
    id = "net.tls_short_lived_or_new_certificate_outbound"
    title = "Public server presented a short-lived or recently issued certificate"
    attack = ("T1573.002", "T1588.004", "T1608.003")
    # Public CA default profiles issue for 45 days or more (the CA/Browser Forum schedule bottoms out at 47 days);
    # only opt-in short-lived profiles and private automation issue for under two weeks.
    SHORT_VALIDITY_DAYS = 14
    # Infrastructure stood up for an operation often gets its certificate just before first use; routine ACME
    # renewal replaces a certificate about every 60 days, so a 2-day window keeps renewals a small fraction.
    FRESH_DAYS = 2
    benign = ("ACME automation with short-lived profiles", "a legitimate site whose certificate was just renewed",
              "clock skew on the server or sensor (for a certificate not yet valid)")
    next_checks = ("which process on the internal host made these connections (host sockets at the same time)",
                   "the server's other names (alt names, DNS answers for it) and how many internal hosts reach it",
                   "beaconing or long connections to the same server")
    card: ClassVar[dict] = {
        "behavior": "an internal client completed a TLS handshake in which a public server presented its own "
                    f"certificate with a validity period of {SHORT_VALIDITY_DAYS} days or less, or one issued less "
                    f"than {FRESH_DAYS} days before the session (or not yet valid at the session time)",
        "telemetry": "Suricata EVE tls (notbefore, notafter) as tls_session and Arkime 6.x cert objects "
                     "(notBefore, notAfter, validDays) as net_session, normalized into tls.server.certificates. "
                     "Present in the lab profile, visible only on TLS 1.2 and earlier handshakes",
        "fidelity": "direct observation of the certificate's validity fields and the session time; says nothing "
                    "about who controls the server",
        "benign_and_cost": "renewed certificates on legitimate sites (about one in thirty sessions to a site that "
                           "renews every 60 days falls in the window), short-lived ACME profiles. One grouped "
                           "finding per (certificate, server address)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal process that opened the connection; the server's other names and prevalence",
        "adds": "no other rule reads certificate validity",
        "research_basis": "ATT&CK Enterprise 20.0 T1588.004 and T1608.003; CA/Browser Forum ballot SC-081 "
                          "validity schedule for the public-CA floor; backlog BL-13. Thresholds are starting "
                          "values for evaluation, not tuned on lab data",
        "retrieval": "the sweep retrieves every record of the network targets in each partition, a superset of "
                     "what this evaluator reads",
        "missing": "an outbound TLS record without a visible server certificate, or whose certificate lacks the "
                   "validity bounds needed, is counted missing, so the negative is partial",
    }

    @staticmethod
    def validity_days(cert: dict) -> float | None:
        """Validity period from the certificate's own bounds, else the source's reported day count."""
        not_before, not_after = _when(cert.get("not_before")), _when(cert.get("not_after"))
        if not_before and not_after:
            return (not_after - not_before).total_seconds() / 86400
        return float(cert["valid_days"]) if isinstance(cert.get("valid_days"), int) else None

    @staticmethod
    def age_days(cert: dict, at: datetime) -> float | None:
        not_before = _when(cert.get("not_before"))
        return None if not_before is None else (at - not_before).total_seconds() / 86400

    def judge(self, e, cert):
        validity, age = self.validity_days(cert), self.age_days(cert, e.ts)
        reasons = []
        if validity is not None and validity <= self.SHORT_VALIDITY_DAYS:
            reasons.append("short-lived")
        if age is not None and age < 0:
            reasons.append("not yet valid")
        elif age is not None and age < self.FRESH_DAYS:
            reasons.append("recently issued")
        if reasons:
            return reasons
        return None if validity is None or age is None else []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            g = self.info[key]
            cert, parts = g["cert"], []
            validity = self.validity_days(cert)
            if "short-lived" in g["reasons"] and validity is not None:
                parts.append(f"its validity period is {validity:.1f} days (at most {self.SHORT_VALIDITY_DAYS})")
            age = self.age_days(cert, g["first"])         # the age at the earliest matching session is the least
            if age is not None and age < 0:
                parts.append(f"it was not yet valid when first presented ({-age * 24:.1f} hours before its "
                             f"notBefore)")
            elif age is not None and age < self.FRESH_DAYS:
                parts.append(f"its notBefore is {age * 24:.1f} hours before the first such session "
                             f"(under {self.FRESH_DAYS} days)")
            claim = (f"{self.summary(key)}: the server presented its certificate ({describe(cert)}), and "
                     f"{'; '.join(parts)}.")
            out.append(Match(self.id, claim, self.claim_type, evs, self.predicate(evs), evs[0].ts, self.severity,
                             self.lane, "medium", evs[0].entities(), group_key=f"{key[0]}|{key[1]}"))
        return out


TLS_PLAYBOOKS = [SelfSignedCertificateOutbound, ShortLivedOrNewCertificateOutbound]
