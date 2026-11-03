"""Native object type pushdown is conditional on the active rule readset and mapping."""
from datetime import timedelta

from romulus.detect.base import Playbook
from romulus.detect.windows_memory_events import LsassProcessAccess
from romulus.evidence.windows_catalog import SECURITY, lookup_event_class
from romulus.hunt.sweep import Sweep
from romulus.report.manifest import _coverage
from romulus.sources.compile import compile_es
from romulus.sources.models import SearchIntent, Window
from tests.test_windows_process_coverage import START, _contract


def sweep_for(pack):
    contract = _contract()
    window = Window(start=START, end=START+timedelta(hours=1))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract})
    sweep.pack = pack
    sweep._windows_read_tokens[contract.target] = {
        lookup_event_class("Security", SECURITY, code).token for code in (4656, 4663)}
    return sweep, contract, window


def test_process_object_filter_compiles_from_native_flattened_contract():
    sweep, contract, window = sweep_for([LsassProcessAccess()])
    groups = sweep._any_of_for(contract.target, contract)
    objects = [group for group in groups if any(p.field == "event.code" and p.value in (4656, 4663) for p in group)]
    assert len(objects) == 2
    assert all(any(p.field == "object.type" and p.value == "Process" for p in group) for group in objects)
    compiled = compile_es(SearchIntent(kind="raw", target=contract.target, window=window, any_of=groups), contract)
    assert "winlog.event_data.ObjectType" in str(compiled.body)
    assert "case_insensitive" in str(compiled.body)


def test_filter_is_not_applied_if_mapping_cannot_push_or_another_rule_needs_objects():
    class Other(Playbook):
        id = "other"
        families = ("object_access",)
    for pack, remove in (([LsassProcessAccess()], True), ([LsassProcessAccess(), Other()], False)):
        sweep, contract, _ = sweep_for(pack)
        if remove:
            contract.fields.pop("object.type")
        assert not any(p.field == "object.type" for group in sweep._any_of_for(contract.target, contract) for p in group)
        assert not sweep.stats["windows_process_object_filter"][contract.target]


def test_no_process_object_auditing_has_standard_no_data_wording():
    result = _coverage([{"rule_id": "win.lsass_process_access", "state": "not_applicable_no_events",
                         "target": "win-host", "partition": "p1", "evaluated": 0, "reasons": []}],
                       targets=["win-host"])
    assert result["rules"][0]["search_result"] == "no data in scope for this rule"
