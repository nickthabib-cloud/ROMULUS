#!/usr/bin/env python3
"""Offline ownership, integrity, and count audit for ROMULUS intelligence assets."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ALLOWED_CLASSES = {
    "authoritative_input",
    "generated_runtime",
    "runtime_configuration",
    "operator_document",
    "historical_design",
}
RETIRED_ASSETS = {
    "docs/research/common-indicator-index.csv",
    "romulus/intelligence/behavior_packs/references.json",
}


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_assets(root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    errors: list[str] = []
    registry_path = root / "romulus" / "intelligence" / "intelligence_assets.json"
    try:
        registry = _read(registry_path)
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "error", "errors": [f"asset registry unreadable: {type(exc).__name__}"], "counts": {}}

    assets = registry.get("assets")
    if not isinstance(assets, list):
        return {"status": "error", "errors": ["asset registry assets must be an array"], "counts": {}}
    seen: set[str] = set()
    for number, asset in enumerate(assets):
        if not isinstance(asset, dict):
            errors.append(f"assets[{number}] is not an object")
            continue
        relative = str(asset.get("path") or "")
        if not relative or relative in seen:
            errors.append(f"assets[{number}] has missing or duplicate path: {relative or '<empty>'}")
        seen.add(relative)
        if asset.get("class") not in ALLOWED_CLASSES:
            errors.append(f"{relative}: invalid asset class")
        if not str(asset.get("owner") or "").strip():
            errors.append(f"{relative}: missing owner")
        if not isinstance(asset.get("consumers"), list) or not asset["consumers"]:
            errors.append(f"{relative}: missing consumers")
        if relative and not (root / relative).is_file():
            errors.append(f"{relative}: declared asset is missing")

    retired = RETIRED_ASSETS | {str(value) for value in registry.get("retired_assets", [])}
    for relative in sorted(retired):
        if relative in seen:
            errors.append(f"retired asset remains declared: {relative}")
        if (root / str(relative)).exists():
            errors.append(f"retired asset still exists: {relative}")

    counts: dict[str, int] = {}
    try:
        corpus = _read(root / "docs" / "research" / "common-indicator-corpus.json")
        entries = corpus["entries"]
        counts["curated_behaviors"] = sum(row.get("record_type") == "curated_behavioral_indicator" for row in entries)
        counts["capability_references"] = sum(row.get("record_type") == "source_capability_reference" for row in entries)
        if corpus.get("status") != "authoritative-build-input":
            errors.append("common indicator corpus has stale source status")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append(f"common indicator corpus unreadable: {type(exc).__name__}")

    try:
        attack = _read(root / "romulus" / "intelligence" / "attack_catalog.json")
        counts["attack_techniques"] = len(attack["techniques"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append(f"ATT&CK catalog unreadable: {type(exc).__name__}")

    pack_dir = root / "romulus" / "intelligence" / "behavior_packs"
    try:
        manifest = _read(pack_dir / "manifest.json")
        for filename, expected in manifest["pack_sha256"].items():
            path = pack_dir / filename
            if not path.is_file():
                errors.append(f"generated pack missing: {filename}")
            elif _sha256(path) != expected:
                errors.append(f"generated pack hash mismatch: {filename}")
        if "references.json" in manifest.get("pack_sha256", {}):
            errors.append("manifest still contains retired references.json")
        capability_pack = _read(pack_dir / "capabilities.json")
        capability_count = len(capability_pack["records"])
        if capability_count != counts.get("capability_references"):
            errors.append(
                f"capability count mismatch: corpus={counts.get('capability_references')} pack={capability_count}"
            )
        if any(row.get("record_type") != "source_capability_reference" for row in capability_pack["records"]):
            errors.append("capabilities pack contains a non-capability record")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append(f"generated behavior packs unreadable: {type(exc).__name__}")

    return {"status": "ok" if not errors else "error", "errors": errors, "counts": counts}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = audit_assets(args.root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
