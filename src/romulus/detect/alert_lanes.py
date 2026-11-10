"""The lane an IDS alert group takes from its sensor's own judgment: the alert's category and priority, and whether
its signature's author tied it to an ATT&CK technique. The alert rule and the process-network link share it, so an
alert keeps one lane wherever it is reported."""
from __future__ import annotations

# Suricata classtypes of the lowest priority that still name attack activity (reconnaissance, a planted string), as
# opposed to protocol decode anomalies, generic events and traffic its author marked not suspicious.
LOW_PRIORITY_ATTACK_CATEGORIES = frozenset({"Detection of a Network Scan", "A suspicious string was detected"})


def alert_stack_lane(category, severity, attack_tagged: bool) -> tuple[str, str]:
    """(lane, severity) of IDS alerts of one category and priority. Traffic the signature author marked not suspicious
    is context. A priority-3 alert is context unless its classtype names attack activity or its signature's metadata
    names an ATT&CK technique: what a signature's author tied to an attack stays visible as a lead."""
    if category == "Not Suspicious Traffic":
        return "context", "low"
    if severity == 3:
        return ("lead", "low") if attack_tagged or category in LOW_PRIORITY_ATTACK_CATEGORIES else ("context", "low")
    return ("high", "high") if severity == 1 else ("lead", "medium")
