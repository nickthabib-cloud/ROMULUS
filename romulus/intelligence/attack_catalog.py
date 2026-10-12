"""Offline access and bounded selection for the generated ATT&CK catalog."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


CATALOG_PATH = Path(__file__).with_name("attack_catalog.json")
EXPECTED_RELEASE = "19.2"
EXPECTED_SOURCE_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
EXPECTED_TECHNIQUE_COUNT = 697
BROAD_PRIORITY_IDS = (
    "T1190", "T1133", "T1078", "T1203", "T1204.002", "T1059", "T1140",
    "T1053.005", "T1543.003", "T1562.001", "T1070.001", "T1036",
    "T1003", "T1552.001", "T1110", "T1087", "T1016", "T1018", "T1046",
    "T1021", "T1021.001", "T1021.002", "T1021.004", "T1047", "T1210",
    "T1105", "T1071.001", "T1071.004", "T1095", "T1571", "T1572", "T1102",
    "T1074", "T1041", "T1567", "T1486", "T1490",
)


def load_attack_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    if not path.is_file():
        return {"metadata": {"status": "not_generated"}, "techniques": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"metadata": {"status": "invalid"}, "techniques": []}
    if not isinstance(value, dict) or not isinstance(value.get("techniques"), list):
        return {"metadata": {"status": "invalid"}, "techniques": []}
    return value


def reference_seeds(objective: str, limit: int = 36, path: Path = CATALOG_PATH) -> list[dict[str, Any]]:
    """Select a compact relevant and tactic-diverse planning view."""
    catalog = load_attack_catalog(path)
    techniques = [row for row in catalog.get("techniques", []) if isinstance(row, dict)]
    if not techniques:
        return []
    objective_tokens = {token for token in re.findall(r"[a-z0-9]{3,}", objective.lower())
                        if token not in {"and", "the", "for", "from", "into", "that", "this", "through", "with",
                                         "across", "activity", "actors", "available", "broad", "conduct", "evidence",
                                         "finding", "find", "historical", "host", "hunt", "identify", "investigate",
                                         "look", "malicious", "network", "possible", "review", "search", "suspected",
                                         "telemetry", "threat"}}

    def compact(row: dict) -> dict:
        strategies = row.get("detection_strategies", []) or []
        analytics = [analytic for strategy in strategies[:3] for analytic in (strategy.get("analytics", []) or [])[:2]]
        components = []
        mutable = []
        for analytic in analytics:
            component = analytic.get("data_component")
            if isinstance(component, dict) and component.get("name") and component["name"] not in components:
                components.append(component["name"])
            for value in analytic.get("mutable_elements", []) or []:
                text = (
                    value.get("field") or value.get("name") or value.get("description")
                    if isinstance(value, dict)
                    else value
                )
                if text and str(text) not in mutable: mutable.append(str(text)[:120])
        return {
            "technique_id": row.get("technique_id"), "name": row.get("name"), "url": row.get("url"),
            "tactic": (row.get("tactics") or [""])[0], "tactics": row.get("tactics", []),
            "platforms": row.get("platforms", []), "is_subtechnique": bool(row.get("is_subtechnique")),
            "detection_strategies": [strategy.get("name") for strategy in strategies[:4] if strategy.get("name")],
            "data_components": components[:6], "mutable_elements": mutable[:6],
        }

    def score(row: dict) -> tuple[int, int, str]:
        text = " ".join([str(row.get("name") or ""), str(row.get("description") or ""),
                         " ".join(str(x.get("name") or "") for x in row.get("detection_strategies", []) or [])]).lower()
        return sum(token in text for token in objective_tokens), int(bool(row.get("detection_strategies"))), str(row.get("technique_id"))

    selected = []
    seen = set()
    by_id = {str(row.get("technique_id")): row for row in techniques if row.get("technique_id")}
    if not objective_tokens:
        for technique_id in BROAD_PRIORITY_IDS:
            row = by_id.get(technique_id)
            if row:
                selected.append(compact(row)); seen.add(technique_id)
                if len(selected) >= limit: return selected
    for row in sorted(techniques, key=score, reverse=True):
        if score(row)[0] <= 0 or row.get("technique_id") in seen: continue
        selected.append(compact(row)); seen.add(row.get("technique_id"))
        if len(selected) >= min(12, limit): break

    by_tactic: dict[str, list[dict]] = {}
    for row in sorted(techniques, key=lambda value: (not bool(value.get("detection_strategies")), str(value.get("technique_id")))):
        for tactic in row.get("tactics", []) or ["unmapped"]:
            by_tactic.setdefault(str(tactic), []).append(row)
    while len(selected) < limit and any(by_tactic.values()):
        progressed = False
        for tactic in sorted(by_tactic):
            while by_tactic[tactic] and by_tactic[tactic][0].get("technique_id") in seen:
                by_tactic[tactic].pop(0)
            if by_tactic[tactic]:
                row = by_tactic[tactic].pop(0); selected.append(compact(row)); seen.add(row.get("technique_id")); progressed = True
                if len(selected) >= limit: break
        if not progressed: break
    return selected[:limit]
