"""Loading and integrity checks for generated behavior knowledge packs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


BEHAVIOR_PACK_DIR = Path(__file__).resolve().parent
PACK_NAMES = ("direct", "sequences", "aggregates", "baselines", "capabilities")


class BehaviorPackError(ValueError):
    """Raised when a generated pack is missing, corrupt, or inconsistent."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BehaviorPackError(f"{path}: unable to read valid JSON ({exc})") from exc


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_behavior_packs(directory: Path = BEHAVIOR_PACK_DIR) -> dict[str, Any]:
    """Load packs only after their generated file hashes match the manifest."""
    directory = Path(directory)
    manifest = _read_json(directory / "manifest.json")
    expected_hashes = manifest.get("pack_sha256")
    if not isinstance(expected_hashes, dict):
        raise BehaviorPackError("manifest.pack_sha256: expected object")
    loaded: dict[str, Any] = {"manifest": manifest}
    for name in PACK_NAMES:
        filename = f"{name}.json"
        path = directory / filename
        expected = expected_hashes.get(filename)
        if not isinstance(expected, str) or not path.is_file():
            raise BehaviorPackError(f"{filename}: pack or manifest hash is missing")
        actual = _sha256(path)
        if actual != expected:
            raise BehaviorPackError(f"{filename}: sha256 does not match manifest")
        pack = _read_json(path)
        if not isinstance(pack, dict) or not isinstance(pack.get("records"), list):
            raise BehaviorPackError(f"{filename}: expected an object with records")
        loaded[name] = pack

    direct = loaded["direct"]["records"]
    direct_ids = [str(row.get("id")) for row in direct]
    if len(set(direct_ids)) != len(direct_ids):
        raise BehaviorPackError("direct.json: duplicate rule IDs")
    for row in direct:
        if row.get("activation_mode") == "active" and row.get("supported") is not True:
            raise BehaviorPackError(f"{row.get('id')}: active rule is not supported")
    capabilities = loaded["capabilities"]["records"]
    if len({str(row.get("id")) for row in capabilities}) != len(capabilities):
        raise BehaviorPackError("capabilities.json: duplicate reference IDs")
    if any(row.get("record_type") != "source_capability_reference" for row in capabilities):
        raise BehaviorPackError("capabilities.json: non-capability record found")
    sequences=loaded["sequences"]["records"]
    for row in sequences:
        status=(row.get("execution") or {}).get("status")
        if status not in {"executable","reference_only"}:
            raise BehaviorPackError(f"{row.get('id')}: sequence execution status is missing")
        if status=="executable" and row.get("supported") is not True:
            raise BehaviorPackError(f"{row.get('id')}: executable sequence is not supported")
    aggregate_primitives={"count","distinct_count","fanout","rate","transition",
        "volume","ratio","duration","periodicity"}
    for row in loaded["aggregates"]["records"]:
        execution=row.get("execution") or {}
        status=execution.get("status")
        if status not in {"executable","reference_only"}:
            raise BehaviorPackError(f"{row.get('id')}: aggregate execution status is missing")
        if status=="executable":
            if row.get("supported") is not True:
                raise BehaviorPackError(f"{row.get('id')}: executable aggregate is not supported")
            if execution.get("primitive") not in aggregate_primitives:
                raise BehaviorPackError(f"{row.get('id')}: aggregate primitive is invalid")
    for row in loaded["baselines"]["records"]:
        execution=row.get("execution") or {}
        status=execution.get("status")
        if status not in {"executable","reference_only"}:
            raise BehaviorPackError(f"{row.get('id')}: baseline execution status is missing")
        if status=="executable":
            if row.get("supported") is not True:
                raise BehaviorPackError(f"{row.get('id')}: executable baseline is not supported")
            if execution.get("primitive") not in {"first_seen","prevalence","deviation"}:
                raise BehaviorPackError(f"{row.get('id')}: baseline primitive is invalid")
    return loaded
