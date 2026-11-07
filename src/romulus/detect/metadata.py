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
                     'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
                     'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
                     'inhibit-response-function', 'impair-process-control'})


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
