"""ATT&CK mitigations (STIX `course-of-action`) and the techniques they mitigate, read offline from the pinned bundles.

Only live objects count: a mitigation or technique that is revoked or deprecated is never cited, and a revoked
technique id is followed to its replacement. The text of each mitigation, and of each `mitigates` relationship (the
technique-specific guidance), is cut to a short summary with the bundle's citation markers removed; the full text
is at the mitigation's ATT&CK page.

Three ATT&CK "mitigations" are not actions: Do Not Mitigate, Pre-compromise and Mitigation Limited or Not Effective.
They say that no preventive control applies, so a technique mapped only to them has no actionable mitigation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .attack import (
    DEFAULT_ATTACK_BUNDLE,
    ICS_ATTACK_BUNDLE,
    ICS_PINNED_JSON_SHA256,
    MAX_UNCOMPRESSED_BYTES,
    PINNED_JSON_SHA256,
    _bounded_gzip_read,
    _external_id,
    _retired,
)

DOMAINS = ("enterprise", "ics")
# ATT&CK entries that state that no preventive control applies, never an action to recommend
NOT_ACTIONABLE = frozenset({"M1055", "M1056", "M0816"})
ATTRIBUTION = ("Mitigation names and summaries are from MITRE ATT&CK (Enterprise and ICS 20.0), "
               "© The MITRE Corporation, reproduced under the ATT&CK terms of use.")
SUMMARY_CHARS = 320
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_SPACE = re.compile(r"\s+")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


@dataclass(frozen=True)
class Mitigation:
    id: str
    name: str
    domain: str
    summary: str
    url: str
    stix_id: str
    actionable: bool


@dataclass(frozen=True)
class MitigatedTechnique:
    id: str
    name: str
    domain: str
    parent_id: str | None


@dataclass(frozen=True)
class MitigationIndex:
    version: MappingProxyType            # domain -> ATT&CK version
    mitigations: MappingProxyType        # (domain, mitigation id) -> Mitigation
    techniques: MappingProxyType         # (domain, technique id) -> MitigatedTechnique, live techniques only
    replacements: MappingProxyType       # (domain, revoked technique id) -> replacement id
    mitigates: MappingProxyType          # (domain, technique id) -> ((mitigation id, guidance), ...)

    def resolve(self, technique_id: str, domain_hint: str | None = None) -> tuple[str, str] | None:
        """(domain, live technique id) for an id as a rule or finding states it; the hinted domain is tried first,
        then the other. A revoked id is followed to its replacement; an unknown or retired id resolves to None."""
        technique_id = str(technique_id).strip().upper()
        order = [domain_hint] if domain_hint in DOMAINS else []
        order += [domain for domain in DOMAINS if domain not in order]
        for domain in order:
            current, seen = technique_id, set()
            while (domain, current) in self.replacements and current not in seen:
                seen.add(current)
                current = self.replacements[(domain, current)]
            if (domain, current) in self.techniques:
                return domain, current
        return None

    def mitigations_for(self, domain: str, technique_id: str) -> tuple[tuple[tuple[str, str], ...], str]:
        """The (mitigation id, guidance) pairs that ATT&CK maps to a live technique, and the basis: the technique
        itself, or, for a sub-technique with none of its own, its parent technique (named in the basis)."""
        own = self.mitigates.get((domain, technique_id), ())
        if own:
            return own, "technique"
        technique = self.techniques.get((domain, technique_id))
        if technique is not None and technique.parent_id:
            inherited = self.mitigates.get((domain, technique.parent_id), ())
            if inherited:
                return inherited, f"parent technique {technique.parent_id}"
        return (), "none"


def clean_text(text: str, limit: int = SUMMARY_CHARS) -> str:
    """A short summary of ATT&CK prose: the first paragraph without citation markers or link targets, cut at a
    sentence end within `limit` characters (with an ellipsis when cut elsewhere)."""
    paragraph = next((part for part in str(text or "").split("\n\n") if part.strip()), "")
    plain = _SPACE.sub(" ", _LINK.sub(r"\1", _CITATION.sub("", paragraph))).strip()
    if plain.endswith(":"):
        # a sentence that introduces a list the summary leaves out
        ends = [match.start() for match in _SENTENCE_END.finditer(plain)]
        plain = plain[:ends[-1]] if ends else plain
    if len(plain) <= limit:
        return plain
    ends = [match.start() for match in _SENTENCE_END.finditer(plain) if match.start() <= limit]
    if ends and ends[-1] >= limit // 3:
        return plain[:ends[-1]]
    return plain[:limit - 1].rstrip() + "…"


def _url(item: dict[str, Any]) -> str:
    for reference in item.get("external_references", ()):
        if reference.get("source_name") == "mitre-attack" and reference.get("url"):
            return str(reference["url"])
    return ""


def _pinned_objects(path: Path, expected_sha256: str) -> list[dict[str, Any]]:
    raw = _bounded_gzip_read(Path(path), MAX_UNCOMPRESSED_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("ATT&CK bundle JSON SHA-256 does not match content/attack/SOURCE.md")
    bundle = json.loads(raw)
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ValueError("ATT&CK document is not a STIX bundle")  # noqa: TRY004 - a malformed file, not a caller bug
    return objects


def _domain_index(objects: list[dict[str, Any]], domain: str, out: dict[str, dict]) -> None:
    collection = next((item for item in objects if item.get("type") == "x-mitre-collection"), {})
    out["version"][domain] = str(collection.get("x_mitre_version", ""))
    patterns = {str(item["id"]): item for item in objects if item.get("type") == "attack-pattern"
                and _external_id(item)}
    live_patterns = {stix_id for stix_id, item in patterns.items() if not any(_retired(item))}
    actions = {str(item["id"]): item for item in objects if item.get("type") == "course-of-action"
               and _external_id(item) and not any(_retired(item))}
    for stix_id, item in actions.items():
        mitigation_id = _external_id(item)
        out["mitigations"][(domain, mitigation_id)] = Mitigation(
            id=mitigation_id, name=str(item.get("name", "")), domain=domain,
            summary=clean_text(item.get("description", "")), url=_url(item), stix_id=stix_id,
            actionable=mitigation_id not in NOT_ACTIONABLE)
    parents: dict[str, str] = {}
    pairs: dict[str, dict[str, str]] = {}
    for item in objects:
        if item.get("type") != "relationship" or any(_retired(item)):
            continue
        source, target = str(item.get("source_ref", "")), str(item.get("target_ref", ""))
        kind = item.get("relationship_type")
        if kind == "subtechnique-of" and source in patterns and target in patterns:
            parents[source] = _external_id(patterns[target])
        elif kind == "revoked-by" and source in patterns and target in patterns:
            out["replacements"][(domain, _external_id(patterns[source]))] = _external_id(patterns[target])
        elif kind == "mitigates" and source in actions and target in live_patterns:
            pairs.setdefault(_external_id(patterns[target]), {})[_external_id(actions[source])] = clean_text(
                item.get("description", ""))
    for stix_id in live_patterns:
        item = patterns[stix_id]
        technique_id = _external_id(item)
        out["techniques"][(domain, technique_id)] = MitigatedTechnique(
            id=technique_id, name=str(item.get("name", "")), domain=domain, parent_id=parents.get(stix_id))
    for technique_id, mapped in pairs.items():
        out["mitigates"][(domain, technique_id)] = tuple(sorted(mapped.items()))


@lru_cache(maxsize=1)
def load_mitigations() -> MitigationIndex:
    """The mitigation index of the pinned Enterprise and ICS bundles (each verified against its pinned digest)."""
    out: dict[str, dict] = {"version": {}, "mitigations": {}, "techniques": {}, "replacements": {}, "mitigates": {}}
    _domain_index(_pinned_objects(DEFAULT_ATTACK_BUNDLE, PINNED_JSON_SHA256), "enterprise", out)
    _domain_index(_pinned_objects(ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256), "ics", out)
    return MitigationIndex(**{key: MappingProxyType(value) for key, value in out.items()})


def index_from_objects(objects_by_domain: dict[str, list[dict]]) -> MitigationIndex:
    """An index built from in-memory STIX objects per domain (fixture subsets); no digest check."""
    out: dict[str, dict] = {"version": {}, "mitigations": {}, "techniques": {}, "replacements": {}, "mitigates": {}}
    for domain, objects in objects_by_domain.items():
        _domain_index(objects, domain, out)
    return MitigationIndex(**{key: MappingProxyType(value) for key, value in out.items()})
