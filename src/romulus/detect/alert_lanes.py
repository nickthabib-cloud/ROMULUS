"""The lane an IDS alert group takes from its sensor's own judgment: the alert's category and priority, and whether
its signature's author tied it to an ATT&CK technique. The alert rule and the process-network link share it, so an
alert keeps one lane wherever it is reported."""
from __future__ import annotations

import re

# Suricata classtypes of the lowest priority that still name attack activity (reconnaissance, a planted string), as
# opposed to protocol decode anomalies, generic events and traffic its author marked not suspicious.
LOW_PRIORITY_ATTACK_CATEGORIES = frozenset({"Detection of a Network Scan", "A suspicious string was detected"})
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
    is context. An alert of priority 3 or lower (4 is the tcp-connection classtype) is context unless its classtype
    names attack activity or its signature's metadata ties it to an attack: what a signature's author tied to an
    attack stays visible as a lead."""
    if category == "Not Suspicious Traffic":
        return "context", "low"
    if isinstance(severity, int) and severity >= 3:
        return ("lead", "low") if attack_tagged or category in LOW_PRIORITY_ATTACK_CATEGORIES else ("context", "low")
    return ("high", "high") if severity == 1 else ("lead", "medium")
