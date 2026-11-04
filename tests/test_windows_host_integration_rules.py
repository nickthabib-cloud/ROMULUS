"""Rule-pack publication, pivot and metadata contracts for typed Windows event signals."""
from romulus.detect.registry import WINDOWS_HOST_PLAYBOOKS, fresh_direct_pack, fresh_pack
from romulus.detect.windows_events import WindowsEventRule
from tests.windows_event_support import event


def test_direct_batches_publish_every_positive_without_staged_recurrence_state():
    [rule] = [rule for rule in fresh_direct_pack() if rule.id == "win.defender_threat"]
    records = [event("defender_event", 1116, offset=number, **{
        "defender.threat.name": "Example", "defender.path": r"C:\Temp\payload.exe",
    }) for number in range(5)]
    matches = rule.consume(records)
    assert len(matches) == 5 and all(match.proposed_lane == "high" for match in matches)
    assert {item.id for match in matches for item in match.events} == {item.id for item in records}
    assert not rule.groups and not rule.members_store and not rule.order
    assert not rule._pending and not rule._fresh and not rule.bounds.pending
    assert rule._spill is None


def test_sweep_instances_retain_disk_backed_folding_and_all_new_rules_are_positive_only():
    ids = {cls.id for cls in WINDOWS_HOST_PLAYBOOKS}
    rules = [rule for rule in fresh_pack() if rule.id in ids and isinstance(rule, WindowsEventRule)]
    assert len(rules) == len(WINDOWS_HOST_PLAYBOOKS)
    assert all(rule.kind == "aggregate" and rule.direct_eligible and not rule.one_shot
               and rule.staged and not rule.assures_negative for rule in rules)
    assert all(rule.attack and rule.benign and rule.next_checks and rule.card["research_basis"] for rule in rules)


def test_declared_required_fields_are_counted_instead_of_silently_judged():
    [rule] = [rule for rule in fresh_pack() if rule.id == "win.registry_run_keys"]
    assert rule.consume([event("registry_change", 13)]) == []
    assert rule.missing_required == 1
    assert rule.coverage_notes()
