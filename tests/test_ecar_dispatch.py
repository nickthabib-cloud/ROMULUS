"""Synthetic eCAR batch identities and unsupported-field accounting.

https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
https://github.com/FiveDirections/OpTC-data/blob/master/errata.md
"""
from copy import deepcopy
from uuid import UUID

from romulus.evidence.ecar import ECAR_DUPLICATE
from romulus.evidence.normalize import normalize_hits
from tests.test_ecar import ecar_hit


def test_duplicate_record_uuid_merges_citations_before_rule_evaluation():
    first = ecar_hit()
    second = deepcopy(first)
    second.update(_id="copy-2", _index="second-endpoint-index")
    third = deepcopy(first)
    third["_id"] = "new-record-same-object"
    third["_source"]["id"] = str(UUID(int=2))
    events, skips, errors = normalize_hits([first, second, third])
    assert not errors and skips == {ECAR_DUPLICATE: 1}
    assert len(events) == 2 and events[0].id != events[1].id
    assert {raw.native_id for raw in events[0].raw} == {"native-1", "copy-2"}
    assert events[0].get("process.entity_id") == events[1].get("process.entity_id")


def test_unknown_fields_are_counted_only_against_the_mapped_family():
    hit = ecar_hit(properties={"image_path": r"C:\Windows\example.exe", "future_property": "not inferred"})
    families, shapes = {}, {}
    events, skips, errors = normalize_hits([hit], skip_families=families, shapes=shapes)
    assert not errors and len(events) == 1 and sum(skips.values()) == 1
    assert list(families.values()) == [frozenset({"process_exec"})]
    assert sum(shapes.values()) == 1
    assert not events[0].has("future_property")


def test_unknown_objects_are_counted_without_claiming_any_known_family():
    families = {}
    events, skips, errors = normalize_hits([ecar_hit("FUTURE_OBJECT", "CREATE")], skip_families=families)
    assert not events and not errors and sum(skips.values()) == 1
    assert list(families.values()) == [frozenset()]


def test_untrusted_object_action_counts_have_an_explicit_bounded_overflow():
    shapes = {}
    rows = [ecar_hit(f"FUTURE_{n}", "CREATE", id=str(UUID(int=n + 1))) for n in range(600)]
    events, skips, errors = normalize_hits(rows, shapes=shapes)
    assert not events and not errors and sum(skips.values()) == 600
    assert len(skips) == 1 and len(shapes) <= 257
    assert sum(shapes.values()) == 600
    assert shapes["ecar:object/action inventory truncated"] > 0


def test_malformed_record_identity_is_an_error_not_a_fabricated_event():
    events, skips, errors = normalize_hits([ecar_hit(id="not-a-uuid")])
    assert not events and not skips and len(errors) == 1
    assert errors[0][1].startswith("ecar:") and "UUID" in errors[0][1]


def test_catalogued_pair_counts_survive_unknown_pair_inventory_overflow():
    shapes = {}
    rows = [ecar_hit(f"FUTURE_{n}", "CREATE", id=str(UUID(int=n + 1))) for n in range(600)]
    rows.append(ecar_hit())
    events, skips, errors = normalize_hits(rows, shapes=shapes)
    assert not errors and len(events) == 1 and sum(skips.values()) == 600
    assert shapes['ecar:["PROCESS","CREATE"]'] == 1
    assert sum(shapes.values()) == 601
    assert len(shapes) <= 258
