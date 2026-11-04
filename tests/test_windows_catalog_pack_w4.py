"""Catalog observations are enabled through the real registered hunt pack."""
from romulus.detect.registry import fresh_pack
from romulus.detect.windows_catalog_events import CATALOG_EVENT_RULES
from romulus.detect.windows_catalog_state import RULES


def test_every_catalog_rule_is_in_the_active_pack_once():
    ids = [rule.id for rule in fresh_pack()]
    for cls in (*CATALOG_EVENT_RULES, *RULES):
        assert ids.count(cls.id) == 1
