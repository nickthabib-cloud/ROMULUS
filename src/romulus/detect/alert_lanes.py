"""The lane an IDS alert group takes from its sensor's own judgment: the alert's category and priority, and whether
its signature's author tied it to an ATT&CK technique. The alert rule and the process-network link share it, so an
alert keeps one lane wherever it is reported."""
from __future__ import annotations

import re

# The stock Suricata classtypes of priority 3 or lower that describe benign or generic traffic rather than an attack:
# the only low-priority alerts kept as context. Any other classtype at a low priority (an attack classtype a site
# re-prioritized, a site rule with no classtype) stays a lead.
BENIGN_LOW_PRIORITY_CATEGORIES = frozenset({"Not Suspicious Traffic", "Unknown Traffic", "Misc activity",
                                            "Generic ICMP event", "Generic Protocol Command Decode",
                                            "A TCP connection was detected"})
# Signature-severity metadata (Emerging Threats' signature_severity) its authors give signatures of real attack activity.
ATTACK_SIGNATURE_SEVERITIES = frozenset({"major", "critical"})
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def attack_tagged(event) -> bool:
    """The alert's signature metadata ties it to an attack: an ATT&CK technique, or a Major/Critical signature
    severity."""
    techniques = event.get("alert.mitre_technique_id")
    severity = event.get("alert.signature_severity")
    return any(isinstance(value, str) and TECHNIQUE_ID.fullmatch(value.strip())
               for value in (techniques if isinstance(techniques, list) else [techniques])) or any(
        isinstance(value, str) and value.strip().casefold() in ATTACK_SIGNATURE_SEVERITIES
        for value in (severity if isinstance(severity, list) else [severity]))


def alert_stack_lane(category, severity, attack_tagged: bool) -> tuple[str, str]:
    """(lane, severity) of IDS alerts of one category and priority. Traffic the signature author marked not suspicious
    is context. An alert of priority 3 or lower (4 is the tcp-connection classtype) is context only when its classtype
    is one of the benign or generic ones and its signature's metadata does not tie it to an attack: any other
    classtype, or none, stays visible as a lead."""
    if category == "Not Suspicious Traffic":
        return "context", "low"
    if isinstance(severity, int) and severity >= 3:
        benign = category in BENIGN_LOW_PRIORITY_CATEGORIES and not attack_tagged
        return ("context", "low") if benign else ("lead", "low")
    return ("high", "high") if severity == 1 else ("lead", "medium")
