"""A source preflight inventories datasets on the index's own mapping, and an incomplete inventory is never read as
an empty one: reports name what may be missing and planners do not treat it as "no datasets"."""
from datetime import UTC, datetime

from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.evidence.windows_catalog import WINDOWS_HOST_DATASETS
from romulus.hunt.manifest import inventory_usable
from romulus.hunt.pivot import PivotExecutor
from romulus.report.manifest import _not_assessed
from romulus.sources.profile import build_profile
from tests.test_zeek_followup_mapping import StrictProfileClient

WINDOWS_FIELDS = ("@timestamp", "event.dataset", "data_stream.dataset", "winlog.computer_name", "winlog.channel",
                  "winlog.provider_name", "winlog.event_id", "winlog.record_id", "winlog.event_data.SourceIp",
                  "winlog.event_data.DestinationIp")
WINDOWS_INVENTORY = {"windows.sysmon_operational": 1000, "windows.security": 500, "windows.perfmon": 40,
                     "custom.app": 7}


def _manifest_profile(profile) -> dict:
    """The manifest entry build_manifest writes for one profile."""
    return {"datasets": profile.datasets, "datasets_complete": not any(
        str(note).startswith("ds inventory truncated") for note in profile.notes)}


def _ip_request() -> EntityTimelineRequest:
    return EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity={"kind": "ip", "value": "10.0.0.5", "role": "src"},
        start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC)))


def test_windows_index_mapping_both_dataset_fields_keeps_its_inventory():
    client = StrictProfileClient(WINDOWS_FIELDS, WINDOWS_INVENTORY, [], {})
    profile, _contract = build_profile(client, "winidx")
    assert any("ds" in body["aggs"] for body in client.bodies)
    assert profile.datasets == WINDOWS_INVENTORY
    assert not any(note.startswith("ds inventory truncated") for note in profile.notes)
    rows = _not_assessed({"source_profiles": {"winidx": _manifest_profile(profile)}},
                         {"stats": {"dataset_filter": {"winidx": list(WINDOWS_HOST_DATASETS)}}})
    assert {(row["dataset"], row["records"]) for row in rows} >= {("custom.app", 7), ("windows.perfmon", 40)}


def test_an_unreadable_inventory_is_named_and_never_planned_as_empty():
    client = StrictProfileClient(("@timestamp", "event.dataset", "host.name", "source.ip", "destination.ip",
                                  "process.pid"), {"linux.audit": 100}, [], {"event.dataset": None})
    profile, contract = build_profile(client, "hostidx")
    entry = _manifest_profile(profile)
    assert profile.datasets == {} and entry["datasets_complete"] is False
    assert not inventory_usable(entry)
    # the planner gets no inventory for the target, so it names what it cannot search instead of planning nothing
    _intents, unresolved = PivotExecutor(None, None, "h1", {"hostidx": contract}, dataset_inventory={}).plan(
        _ip_request())
    assert unresolved and all(cell.status == "partial" for cell in unresolved)
    rows = _not_assessed({"source_profiles": {"hostidx": entry}},
                         {"stats": {"dataset_filter": {"hostidx": ["linux.audit"]}}})
    assert any(row["records"] is None and "could not list every dataset" in row["count_scope"] for row in rows)


def test_a_capped_inventory_stays_usable_and_says_others_may_exist():
    entry = {"datasets": {"linux.audit": 5, "custom.x": 3}, "datasets_complete": False}
    assert inventory_usable(entry)
    rows = _not_assessed({"source_profiles": {"t": entry}}, {"stats": {"dataset_filter": {"t": ["linux.audit"]}}})
    assert ("custom.x", 3) in {(row["dataset"], row["records"]) for row in rows}
    assert any(row["records"] is None for row in rows)


def test_hunts_recorded_before_the_completeness_flag_read_as_before():
    assert inventory_usable({"datasets": {}}) and inventory_usable({"datasets": {"a": 1}})
    rows = _not_assessed({"source_profiles": {"t": {"datasets": {"a": 1}}}},
                         {"stats": {"dataset_filter": {"t": ["a"]}}})
    assert rows == []
