"""Build ROMULUS's compact, pinned ATT&CK reference catalog from official STIX.

The generated JSON is safe to use offline during a hunt. Updating it is an
explicit maintainer action so production investigations never depend on live
Internet access or a moving ATT&CK branch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen


DEFAULT_RELEASE = "19.2"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-{release}.json"
)


def _active(item: dict) -> bool:
    return not item.get("revoked") and not item.get("x_mitre_deprecated")


def _external(item: dict) -> tuple[str, str]:
    for ref in item.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url") or "")
    for ref in item.get("external_references", []):
        if ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url") or "")
    return "", ""


def _description(item: dict, limit: int = 800) -> str:
    value = re.sub(r"\s+", " ", str(item.get("description") or "")).strip()
    return value[:limit]


def _log_sources(item: dict) -> list[dict[str, str]]:
    rows = []
    for value in item.get("x_mitre_log_sources", []) or []:
        if not isinstance(value, dict):
            continue
        name = str(value.get("name") or "").strip()
        channel = str(value.get("channel") or "").strip()
        if name and channel and {"name": name, "channel": channel} not in rows:
            rows.append({"name": name, "channel": channel})
    return rows


def build_catalog(bundle: dict, release: str, source_url: str, source_sha256: str) -> dict:
    objects = bundle.get("objects")
    if bundle.get("type") != "bundle" or not isinstance(objects, list):
        raise ValueError("ATT&CK source is not a STIX bundle")
    active = {str(item.get("id")): item for item in objects if isinstance(item, dict) and item.get("id") and _active(item)}
    relationships = [item for item in active.values() if item.get("type") == "relationship"]
    strategies = {key: value for key, value in active.items() if value.get("type") == "x-mitre-detection-strategy"}
    analytics = {key: value for key, value in active.items() if value.get("type") == "x-mitre-analytic"}
    components = {key: value for key, value in active.items() if value.get("type") == "x-mitre-data-component"}
    techniques = {key: value for key, value in active.items() if value.get("type") == "attack-pattern"}

    detects: dict[str, list[str]] = {}
    parents: dict[str, str] = {}
    legacy_components: dict[str, list[str]] = {}
    for rel in relationships:
        source = str(rel.get("source_ref") or "")
        target = str(rel.get("target_ref") or "")
        relation = rel.get("relationship_type")
        if relation == "detects" and source in strategies and target in techniques:
            detects.setdefault(target, []).append(source)
        elif relation == "detects" and source in components and target in techniques:
            legacy_components.setdefault(target, []).append(source)
        elif relation == "subtechnique-of" and source in techniques and target in techniques:
            parents[source] = target

    rows = []
    for stix_id, technique in techniques.items():
        technique_id, url = _external(technique)
        if not technique_id.startswith("T"):
            continue
        strategy_rows = []
        for strategy_ref in sorted(set(detects.get(stix_id, []))):
            strategy = strategies[strategy_ref]
            strategy_id, strategy_url = _external(strategy)
            analytic_rows = []
            for analytic_ref in strategy.get("x_mitre_analytic_refs", []) or []:
                analytic = analytics.get(str(analytic_ref))
                if not analytic:
                    continue
                analytic_id, analytic_url = _external(analytic)
                component_ref = str(analytic.get("x_mitre_data_component_ref") or "")
                component = components.get(component_ref, {})
                component_id, component_url = _external(component)
                analytic_rows.append({
                    "analytic_id": analytic_id,
                    "name": str(analytic.get("name") or ""),
                    "url": analytic_url,
                    "description": _description(analytic),
                    "platforms": sorted(set(analytic.get("x_mitre_platforms", []) or [])),
                    "mutable_elements": analytic.get("x_mitre_mutable_elements", []) or [],
                    "data_component": {
                        "data_component_id": component_id,
                        "name": str(component.get("name") or ""),
                        "url": component_url,
                        "log_sources": _log_sources(component),
                    } if component else None,
                })
            strategy_rows.append({
                "strategy_id": strategy_id,
                "name": str(strategy.get("name") or ""),
                "url": strategy_url,
                "description": _description(strategy),
                "analytics": analytic_rows,
            })
        parent_id = ""
        if parents.get(stix_id):
            parent_id, _ = _external(techniques[parents[stix_id]])
        legacy = []
        for component_ref in sorted(set(legacy_components.get(stix_id, []))):
            component = components[component_ref]
            component_id, component_url = _external(component)
            legacy.append({"data_component_id": component_id, "name": str(component.get("name") or ""),
                           "url": component_url, "log_sources": _log_sources(component)})
        rows.append({
            "technique_id": technique_id,
            "name": str(technique.get("name") or ""),
            "url": url,
            "description": _description(technique),
            "tactics": sorted({str(x.get("phase_name")) for x in technique.get("kill_chain_phases", []) if x.get("phase_name")}),
            "platforms": sorted(set(technique.get("x_mitre_platforms", []) or [])),
            "is_subtechnique": bool(technique.get("x_mitre_is_subtechnique")),
            "parent_technique_id": parent_id,
            "detection_strategies": strategy_rows,
            "legacy_data_components": legacy,
        })
    rows.sort(key=lambda row: tuple(int(piece) if piece.isdigit() else piece for piece in re.split(r"[.]", row["technique_id"][1:])))
    strategy_count = sum(len(row["detection_strategies"]) for row in rows)
    analytic_count = sum(len(strategy["analytics"]) for row in rows for strategy in row["detection_strategies"])
    return {
        "metadata": {
            "domain": "enterprise-attack", "release": release, "source_url": source_url,
            "source_sha256": source_sha256, "attack_spec_versions": sorted({str(x.get("x_mitre_attack_spec_version")) for x in active.values() if x.get("x_mitre_attack_spec_version")}),
            "technique_count": len(rows), "detection_strategy_links": strategy_count,
            "analytic_links": analytic_count,
        },
        "techniques": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the compact ROMULUS ATT&CK catalog from an official pinned STIX release")
    parser.add_argument("--release", default=DEFAULT_RELEASE)
    parser.add_argument("--url", help="Override the official pinned-release URL")
    parser.add_argument("--expected-sha256", help="Reject the download unless it has this SHA-256")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "romulus" / "intelligence" / "attack_catalog.json")
    args = parser.parse_args()
    url = args.url or DEFAULT_URL.format(release=args.release)
    request = Request(url, headers={"User-Agent": "ROMULUS ATTACK catalog updater"})
    with urlopen(request, timeout=120) as response:
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    if args.expected_sha256 and digest.lower() != args.expected_sha256.lower():
        raise ValueError(f"ATT&CK bundle SHA-256 mismatch: expected {args.expected_sha256}, got {digest}")
    catalog = build_catalog(json.loads(payload), args.release, url, digest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(catalog["metadata"], indent=2))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
