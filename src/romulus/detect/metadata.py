"""Hunt-scoped rule metadata without creating detector state or changing the registry."""
from __future__ import annotations

import re
from types import SimpleNamespace

from sqlalchemy import select

from romulus.store import schema as t
from romulus.store.db import read_snapshot

_SIGMA_ID = re.compile(r'sigma\.[0-9a-f]{64}\Z')
_NETWORK_CATEGORIES = frozenset({'network_connection', 'dns', 'dns_query', 'proxy', 'firewall', 'webserver'})
_TACTICS = frozenset({'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
                     'privilege-escalation', 'defense-evasion', 'stealth', 'defense-impairment', 'evasion',
                     'credential-access', 'discovery',
                     'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
                     'inhibit-response-function', 'impair-process-control'})


# Tactics for techniques the vendored ATT&CK release (Enterprise and ICS) does not define. Every technique is
# resolved through the vendored release first; this table is only the fallback for an id it lacks.
RULE_TECHNIQUE_TACTICS = {
    "T1190": ("initial-access",),
    "T1078": ("initial-access", "persistence", "privilege-escalation", "defense-evasion"),
    "T1059": ("execution",), "T1059.004": ("execution",), "T1059.006": ("execution",),
    "T1505.003": ("persistence",), "T1098.004": ("persistence",),
    "T1003.008": ("credential-access",), "T1021.004": ("lateral-movement",),
    "T1033": ("discovery",), "T1082": ("discovery",), "T1016": ("discovery",),
    "T1087": ("discovery",), "T1069": ("discovery",), "T1046": ("discovery",),
    "T1036.005": ("defense-evasion",), "T1562.004": ("defense-evasion",),
    "T1105": ("command-and-control",), "T1071": ("command-and-control",),
    "T1071.001": ("command-and-control",), "T1095": ("command-and-control",),
    "T1571": ("command-and-control",), "T1029": ("command-and-control",),
    "T1573": ("command-and-control",), "T1498": ("impact",),
    "T1590.002": ("reconnaissance",), "T1595.001": ("reconnaissance",),
    "T1595.002": ("reconnaissance",), "T1595.003": ("reconnaissance",),
}


# Legacy tactic names a rule's tags may still carry, split by the current ATT&CK release: a tag alone cannot say
# which of the new tactics it meant, so it stands for the group of them.
LEGACY_TACTIC_ALTERNATIVES = {"defense-evasion": ("defense-impairment", "stealth")}


def finding_attack(explicit_attack, rule, *, groups: bool = False) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """One finding's ATT&CK techniques and tactics: the techniques stored with the finding when it has them, else its
    rule's (an imported rule's technique tags included), each resolved through the vendored ATT&CK release
    (Enterprise and ICS), with RULE_TECHNIQUE_TACTICS only for an id the release lacks. A rule that names tactics
    but no technique (an imported rule tagged only with a tactic) keeps its tactic names; a legacy name the release
    split (LEGACY_TACTIC_ALTERNATIVES) is one tactic naming its alternatives (`a or b`), or with `groups` one `a|b`
    group, which tactic breadth counts as a single choice. Every consumer (incident graph, ranking) reads tactics through this mapping."""
    from romulus.content.attack_tags import technique_tactics

    attack = tuple(explicit_attack or getattr(rule, "attack", ()))
    if not attack:
        named: set[str] = set()
        for tactic in getattr(rule, "tactics", ()) or ():
            alternatives = LEGACY_TACTIC_ALTERNATIVES.get(tactic)
            if alternatives is None:
                named.add(tactic)
            else:
                named.add(("|" if groups else " or ").join(alternatives))
        return attack, tuple(sorted(named))
    tactics = {tactic for technique in attack
               for tactic in (technique_tactics((technique,)) or RULE_TECHNIQUE_TACTICS.get(technique, ()))}
    return attack, tuple(sorted(tactics))


def is_sigma_id(rule_id):
    return isinstance(rule_id, str) and _SIGMA_ID.fullmatch(rule_id) is not None


def pinned_rule_ids(manifest):
    """The detector ids the hunt declared, including its separate local Sigma pin."""
    ids = {item['id'] for item in (manifest.get('pack') or {}).get('playbooks', [])
           if isinstance(item, dict) and item.get('id')}
    ids.update('sigma.' + item['id'] for item in (manifest.get('sigma_rules') or {}).get('applied', [])
               if isinstance(item, dict) and is_sigma_id('sigma.' + str(item.get('id', ''))))
    return ids


def hunt_rule_metadata(repo, hunt_id=None, *, manifest=None, rule_ids=None):
    """Return the static classes plus lightweight metadata for this hunt's pinned Sigma content.

    Attribution, tags and activation choices come from the immutable pin. The mapping is read only when its
    content identity agrees with that pin. Reports can still show the pinned attribution if content is missing.
    Imports stay local to this call so detector modules may consume the resolver without a registry cycle.
    """
    from romulus.detect.registry import ALL_PLAYBOOKS
    from romulus.detect.sigma import SigmaRule

    rules = {playbook.id: playbook for playbook in ALL_PLAYBOOKS}
    if manifest is None:
        hunt = repo.get_hunt(hunt_id) if hasattr(repo, 'get_hunt') else None
        manifest = (hunt or {}).get('manifest') or {}
    pins = (manifest.get('sigma_rules') or {}).get('applied', [])
    if rule_ids is not None:
        selected = set(rule_ids)
        pins = [pin for pin in pins if 'sigma.' + pin['id'] in selected]
    mappings = {}
    if pins and hasattr(repo, 'engine'):
        with read_snapshot(repo.engine) as c:
            for pin in pins:
                row = c.execute(select(t.sigma_rule.c.mapping).where(
                    t.sigma_rule.c.id == pin['id'], t.sigma_rule.c.digest == pin['digest'])).scalar()
                if row is not None:
                    mappings[pin['id']] = row
    for pin in pins:
        rule_id = 'sigma.' + str(pin.get('id', ''))
        if not is_sigma_id(rule_id):
            continue
        mapping = mappings.get(pin['id'], {})
        category = mapping.get('category') or (pin.get('logsource') or {}).get('category', '')
        tags = tuple(str(tag).lower() for tag in pin.get('tags', ()))
        attack = tuple(dict.fromkeys(tag.removeprefix('attack.').upper() for tag in tags
                                    if re.fullmatch(r'attack\.t\d{4}(?:\.\d{3})?', tag)))
        tactics = tuple(sorted({tag.removeprefix('attack.').replace('_', '-') for tag in tags
                               if tag.removeprefix('attack.').replace('_', '-') in _TACTICS}))
        rules[rule_id] = SimpleNamespace(
            id=rule_id, title=pin.get('title', rule_id), version='3+' + pin['digest'],
            lane=pin.get('lane', 'lead'), severity={'informational': 'info'}.get(
                pin.get('level'), pin.get('level', 'medium')),
            attack=attack, tactics=tactics, kind='aggregate',
            anchor_class='network_observation' if category in _NETWORK_CATEGORIES else 'execution',
            assures_negative=False, positive_only_reason=SigmaRule.positive_only_reason,
            families=tuple(mapping.get('families', ())), category=category,
            os_families=tuple(mapping.get('os_families', ('linux', 'windows', 'unknown'))),
        )
    return rules
