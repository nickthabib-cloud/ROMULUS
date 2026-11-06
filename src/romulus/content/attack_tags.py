"""Validate analyst technique context against the shipped ATT&CK release."""
from functools import lru_cache

from romulus.catalog.attack import (
    ICS_ATTACK_BUNDLE,
    ICS_PINNED_JSON_SHA256,
    load_attack_bundle,
)


@lru_cache(maxsize=1)
def _techniques():
    techniques, replacements = {}, {}
    for bundle in (load_attack_bundle(), load_attack_bundle(
            ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256)):
        techniques.update((technique.id, technique) for technique in bundle.techniques)
        replacements.update(bundle.replacements)
    return techniques, replacements


def validate_attack(values):
    """Keep live techniques and return bounded, value-free validation notes."""
    values = tuple(dict.fromkeys(values))
    if not values:
        return (), []
    techniques, replacements = _techniques()
    accepted, notes = [], []
    for value in values:
        technique = techniques.get(value.upper())
        if technique is None:
            notes.append({'reason': 'attack_unknown', 'id': value})
        elif technique.revoked or technique.deprecated:
            note = {'reason': 'attack_revoked' if technique.revoked else 'attack_deprecated', 'id': value}
            if replacement := replacements.get(value.upper()):
                note['replacement'] = replacement
            notes.append(note)
        else:
            accepted.append(value.upper())
    return tuple(accepted), notes


def technique_tactics(values):
    """Resolve tactic names for already validated per-finding technique context."""
    values = tuple(values)
    if not values:
        return ()
    techniques, _replacements = _techniques()
    return tuple(sorted({tactic for value in values if value in techniques
                         for tactic in techniques[value].tactics}))
