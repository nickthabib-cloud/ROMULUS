"""Bounded loader for the pinned ATT&CK Enterprise STIX bundle."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .models import (
    AttackDataComponent,
    AttackDataSource,
    AttackKnowledge,
    AttackTactic,
    AttackTechnique,
)

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ATTACK_BUNDLE = ROOT / "content" / "attack" / "enterprise-attack-20.0.json.gz"
PINNED_JSON_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


def _bounded_gzip_read(path: Path, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    with gzip.open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"ATT&CK bundle exceeds uncompressed byte limit ({limit})")
            chunks.append(chunk)
    return b"".join(chunks)


def _external_id(item: dict[str, Any], source: str = "mitre-attack") -> str:
    for reference in item.get("external_references", ()):
        if reference.get("source_name") == source and reference.get("external_id"):
            return str(reference["external_id"])
    return ""


def _retired(item: dict[str, Any]) -> tuple[bool, bool]:
    return bool(item.get("revoked", False)), bool(item.get("x_mitre_deprecated", False))


def _log_source_label(item: dict[str, Any]) -> str:
    name = str(item.get("name", "")).strip()
    channel = str(item.get("channel", "")).strip()
    return f"{name} ({channel})" if name and channel else name or channel


def load_attack_bundle(
    path: Path = DEFAULT_ATTACK_BUNDLE,
    *,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES,
    expected_sha256: str | None = PINNED_JSON_SHA256,
) -> AttackKnowledge:
    """Load ATT&CK with a hard decompression bound and validate the pinned JSON digest."""
    raw = _bounded_gzip_read(Path(path), max_uncompressed_bytes)
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("ATT&CK bundle JSON SHA-256 does not match content/attack/SOURCE.md")
    try:
        bundle = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ATT&CK bundle is not valid UTF-8 STIX JSON") from exc
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("ATT&CK document is not a STIX bundle")
    objects: list[dict[str, Any]] = bundle["objects"]

    collections = [item for item in objects if item.get("type") == "x-mitre-collection"]
    if len(collections) != 1 or not collections[0].get("x_mitre_version"):
        raise ValueError("ATT&CK bundle must contain one versioned collection")
    version = str(collections[0]["x_mitre_version"])

    tactics = tuple(
        sorted(
            (
                AttackTactic(
                    id=_external_id(item),
                    stix_id=str(item["id"]),
                    name=str(item["name"]),
                    shortname=str(item["x_mitre_shortname"]),
                    revoked=_retired(item)[0],
                    deprecated=_retired(item)[1],
                )
                for item in objects
                if item.get("type") == "x-mitre-tactic" and _external_id(item)
            ),
            key=lambda item: item.id,
        )
    )

    data_sources = tuple(
        sorted(
            (
                AttackDataSource(
                    id=_external_id(item),
                    stix_id=str(item["id"]),
                    name=str(item["name"]),
                    platforms=tuple(sorted(map(str, item.get("x_mitre_platforms", ())))),
                    revoked=_retired(item)[0],
                    deprecated=_retired(item)[1],
                )
                for item in objects
                if item.get("type") == "x-mitre-data-source" and _external_id(item)
            ),
            key=lambda item: item.id,
        )
    )

    component_objects = {
        str(item["id"]): item for item in objects if item.get("type") == "x-mitre-data-component"
    }
    data_components = tuple(
        sorted(
            (
                AttackDataComponent(
                    id=_external_id(item),
                    stix_id=stix_id,
                    name=str(item["name"]),
                    log_sources=tuple(
                        sorted(
                            filter(
                                None,
                                (_log_source_label(source) for source in item.get("x_mitre_log_sources", ())),
                            )
                        )
                    ),
                    revoked=_retired(item)[0],
                    deprecated=_retired(item)[1],
                )
                for stix_id, item in component_objects.items()
                if _external_id(item)
            ),
            key=lambda item: item.id,
        )
    )

    technique_objects = {
        str(item["id"]): item
        for item in objects
        if item.get("type") == "attack-pattern" and _external_id(item)
    }
    technique_ids = {stix_id: _external_id(item) for stix_id, item in technique_objects.items()}
    parents: dict[str, str] = {}
    replacements: dict[str, str] = {}
    strategies_by_technique: dict[str, set[str]] = {}
    for item in objects:
        if item.get("type") != "relationship" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        source = str(item.get("source_ref", ""))
        target = str(item.get("target_ref", ""))
        if (
            item.get("relationship_type") == "subtechnique-of"
            and source in technique_ids
            and target in technique_ids
        ):
            parents[source] = technique_ids[target]
        elif (
            item.get("relationship_type") == "revoked-by"
            and source in technique_ids
            and target in technique_ids
        ):
            replacements[technique_ids[source]] = technique_ids[target]
        elif item.get("relationship_type") == "detects" and target in technique_ids:
            strategies_by_technique.setdefault(target, set()).add(source)

    analytics = {
        str(item["id"]): item
        for item in objects
        if item.get("type") == "x-mitre-analytic" and not any(_retired(item))
    }
    strategies = {
        str(item["id"]): item
        for item in objects
        if item.get("type") == "x-mitre-detection-strategy" and not any(_retired(item))
    }
    technique_components: dict[str, set[str]] = {}
    technique_sources: dict[str, set[str]] = {}
    for technique_stix, strategy_ids in strategies_by_technique.items():
        for strategy_id in strategy_ids:
            strategy = strategies.get(strategy_id, {})
            for analytic_id in strategy.get("x_mitre_analytic_refs", ()):
                analytic = analytics.get(str(analytic_id), {})
                for source in analytic.get("x_mitre_log_source_references", ()):
                    component = component_objects.get(str(source.get("x_mitre_data_component_ref", "")))
                    if component and not any(_retired(component)):
                        technique_components.setdefault(technique_stix, set()).add(str(component["name"]))
                    if label := _log_source_label(source):
                        technique_sources.setdefault(technique_stix, set()).add(label)

    techniques = tuple(
        sorted(
            (
                AttackTechnique(
                    id=technique_ids[stix_id],
                    stix_id=stix_id,
                    name=str(item["name"]),
                    is_subtechnique=bool(item.get("x_mitre_is_subtechnique", False)),
                    parent_id=parents.get(stix_id),
                    tactics=tuple(
                        sorted(
                            str(phase["phase_name"])
                            for phase in item.get("kill_chain_phases", ())
                            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
                        )
                    ),
                    platforms=tuple(sorted(map(str, item.get("x_mitre_platforms", ())))),
                    data_sources=tuple(sorted(technique_sources.get(stix_id, ()))),
                    data_components=tuple(sorted(technique_components.get(stix_id, ()))),
                    revoked=_retired(item)[0],
                    deprecated=_retired(item)[1],
                )
                for stix_id, item in technique_objects.items()
            ),
            key=lambda item: item.id,
        )
    )
    return AttackKnowledge(
        version=version,
        tactics=tactics,
        techniques=techniques,
        data_sources=data_sources,
        data_components=data_components,
        replacements=MappingProxyType(dict(sorted(replacements.items()))),
    )
