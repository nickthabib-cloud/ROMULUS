"""Windows coverage requires inventory, streaming continuity, and site collection attestations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.base import Playbook
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.evidence.windows import RecordIdContinuity
from romulus.evidence.windows_catalog import (
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    collection_requirements,
    lookup_event_class,
)
from romulus.hunt.sweep import Sweep
from romulus.site import load_site_facts
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types

START = datetime(2026, 1, 2, tzinfo=UTC)


def _hit(record_id: int | str, event_id: int = 1, *, native_id: str | None = None):
    return {
        "_index": "logs-windows",
        "_id": native_id or f"w-{record_id}",
        "_source": {
            "@timestamp": "2026-01-02T00:05:00Z",
            "agent": {"type": "winlogbeat"},
            "event": {"dataset": "windows.sysmon_operational"},
            "winlog": {
                "channel": SYSMON_CHANNEL,
                "provider_name": SYSMON,
                "event_id": event_id,
                "computer_name": "WS01.example.test",
                "record_id": record_id,
                "event_data": {"ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"},
            },
        },
    }


class WindowsProcessRule(Playbook):
    id = "test.windows.process"
    title = "test"
    families = ("process_exec",)
    os_families = ("windows",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)


class UndeclaredWindowsProcessRule(Playbook):
    id = "test.windows.process.undeclared"
    title = "test"
    families = ("process_exec",)
    os_families = ("windows",)


def _contract():
    return contract_from_types(
        "target-name-is-irrelevant",
        {
            "@timestamp": "date",
            "event.dataset": "keyword",
            "winlog.channel": "keyword",
            "winlog.provider_name": "keyword",
            "winlog.event_id": "long",
            "winlog.computer_name": "keyword",
            "winlog.record_id": "long",
            "winlog.event_data": "flattened",
        },
        role="host",
        hosts=("ws01.example.test",),
    )


def _site(tmp_path, *, event_ids: str = "[1]"):
    path = tmp_path / "site" / "collection.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        f"      event_ids: {event_ids}\n",
        encoding="utf-8",
    )
    return load_site_facts(tmp_path)


def test_record_id_gap_scan_is_streaming_duplicate_safe_and_names_each_gap():
    continuity = RecordIdContinuity()

    first = continuity.observe("target", [_hit(10), _hit(10, native_id="duplicate"), _hit(13)])
    second = continuity.observe("target", [_hit(12), _hit("bad")])

    assert first == [
        f"shipper gaps: 2 records missing on {SYSMON_CHANNEL} for ws01.example.test"
    ]
    assert any("out of order" in reason for reason in second)
    assert any("non-numeric" in reason for reason in second)
    assert len(continuity.last) == 1


def test_record_id_continuity_refuses_singletons_and_bounds_host_channel_state():
    continuity = RecordIdContinuity(max_keys=1)

    singleton = continuity.observe("target", [_hit(10)])
    second_host = _hit(20)
    second_host["_source"]["winlog"]["computer_name"] = "ws02.example.test"
    overflow = continuity.observe("target", [second_host])

    assert any("fewer than two" in reason for reason in singleton)
    assert any("capacity" in reason for reason in overflow)
    assert len(continuity.last) == 1


def test_windows_coverage_gate_requires_inventory_continuity_and_matching_attestation(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    assert sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10), _hit(11)], []) == []
    assert sweep._windows_rule_reasons(
        contract.target,
        contract,
        rule,
        [_hit(10)],
        ["shipper gaps: 1 records missing on channel"],
    ) == ["shipper gaps: 1 records missing on channel"]

    sweep._windows_inventory[contract.target] = set()
    missing = sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10)], [])
    assert any("absent from source inventory" in reason for reason in missing)

    unattested = Sweep(None, None, "h1", window, {contract.target: contract})
    unattested._windows_inventory[contract.target] = {event_class.token}
    unattested._windows_inventory_reasons[contract.target] = []
    missing = unattested._windows_rule_reasons(contract.target, contract, rule, [_hit(10)], [])
    assert missing == ["collection not attested: Sysmon event id 1 on ws01.example.test"]

    truncated = contract.model_copy(update={"host_inventory_complete": False})
    missing = sweep._windows_rule_reasons(
        truncated.target, truncated, rule, [_hit(10), _hit(11)], [],
    )
    assert "collection not attested: source host inventory truncated" in missing


def test_windows_partition_requires_channel_liveness_at_both_edges(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(hours=6))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    early = _hit(10)
    early["_source"]["@timestamp"] = (START + timedelta(minutes=5)).isoformat()
    late = _hit(11)
    late["_source"]["@timestamp"] = (START + timedelta(hours=5, minutes=55)).isoformat()

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [early], [], window)
    head_reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [late], [], window)
    live_reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [early, late], [], window)

    assert reasons == [
        "no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
        "after 2026-01-02T00:05:00+00:00"
    ]
    assert head_reasons == [
        "no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
        "before 2026-01-02T05:55:00+00:00"
    ]
    assert live_reasons == []


def test_rule_without_declared_classes_requires_every_catalog_class_for_its_family(tmp_path):
    contract = _contract()
    rule = UndeclaredWindowsProcessRule()
    window = Window(start=START, end=START + timedelta(minutes=5))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    sysmon = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    security = lookup_event_class("Security", SECURITY, 4688)
    assert sysmon is not None and security is not None
    sweep._windows_inventory[contract.target] = {sysmon.token}
    sweep._windows_inventory_reasons[contract.target] = []

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10), _hit(11)], [])

    assert any("Security|Microsoft-Windows-Security-Auditing|4688" in reason for reason in reasons)


def test_skip_reason_state_is_bounded_without_losing_the_total_count():
    sweep = object.__new__(Sweep)
    sweep.stats = {"skips": {}}
    additions = {f"Windows event class unknown-{number}": number + 1 for number in range(400)}

    sweep._record_skips("windows-target", additions)

    assert len(sweep.stats["skips"]) == 257
    assert len(sweep.stats["skips_by_target"]["windows-target"]) == 257
    assert sum(sweep.stats["skips"].values()) == sum(additions.values())


def test_system_channel_collection_requires_an_explicit_event_log_attestation():
    event_class = lookup_event_class("System", "Service Control Manager", 7045)

    assert event_class is not None
    assert collection_requirements(event_class) == (
        ("system_event_log", {}, "Windows System event log"),
    )


def test_security_1102_uses_eventlog_provider_and_security_channel_attestation():
    event_class = lookup_event_class("Security", "Microsoft-Windows-Eventlog", 1102)

    assert event_class is not None
    assert lookup_event_class("Security", SECURITY, 1102) is None
    assert collection_requirements(event_class) == (
        ("security_event_log", {}, "Windows Security event log"),
    )


def test_event_class_inventory_is_a_bounded_aggregate_over_the_full_hunt_window(monkeypatch):
    from romulus.hunt import sweep as sweep_module

    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(
            target=intent.target,
            fingerprint="inventory",
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=10_000,
            total_relation="eq",
            returned=1,
            buckets=[{
                "key": {
                    "event.channel": SYSMON_CHANNEL,
                    "event.provider": SYSMON,
                    "event.code": 1,
                },
                "count": 10_000,
            }],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(None, object(), "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })

    sweep._prepare_windows_inventory(contract.target, contract)

    [intent] = seen
    assert intent.kind == "aggregate" and intent.window == sweep.window
    assert intent.group_by == ["event.channel", "event.provider", "event.code"]
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    assert sweep._windows_inventory[contract.target] == {event_class.token}


def test_catalogued_windows_class_with_no_reader_is_counted_as_not_assessed(monkeypatch):
    from romulus.hunt import sweep as sweep_module

    def execute(_client, intent, _contract):
        return SearchOutcome(
            target=intent.target, fingerprint="inventory", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=9, total_relation="eq", returned=1,
            buckets=[{
                "key": {
                    "event.channel": "System",
                    "event.provider": "Service Control Manager",
                    "event.code": 7045,
                },
                "count": 9,
            }],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(None, object(), "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })
    sweep.pack = [WindowsProcessRule()]

    sweep._prepare_windows_inventory(contract.target, contract)

    assert sweep.stats["windows_unassessed"][contract.target] == [{
        "channel": "System", "provider": "Service Control Manager", "event_id": 7045,
        "family": "service_change", "records": 9,
    }]


def test_unknown_windows_classes_are_not_assessed_without_poisoning_every_rule():
    events, skips, errors = normalize_hits([_hit(10, event_id=9999)])

    assert events == [] and errors == [] and sum(skips.values()) == 1
    assert Sweep._unsupported_skips(skips) == {}
    assert any("Windows event class" in reason and "not normalized" in reason for reason in skips)


def test_playbook_os_families_filter_before_required_field_evaluation():
    [windows], _skips, _errors = normalize_hits([_hit(10)])
    linux = TypedEvent(
        id="linux",
        family="process_exec",
        ts=START,
        host="host1",
        fields={},
        raw=[RawRef(target="linux", native_id="1")],
        normalizer="lab-ecs@9",
    )
    rule = WindowsProcessRule()

    assert rule.applicable([linux, windows]) == [windows]
    assert rule.evaluated == 1 and rule.missing_required == 0


def test_existing_linux_rules_do_not_silently_widen_to_windows_events():
    windows_families = {event.family for event in EVENT_CLASSES}
    windows_enabled = {
        playbook.id
        for playbook in ALL_PLAYBOOKS
        if windows_families.intersection(playbook.families) and "windows" in playbook.os_families
    }

    assert windows_enabled == {"ioc.indicator_match"}


def test_wrong_os_same_family_is_not_a_complete_negative(monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    linux = TypedEvent(
        id="linux",
        family="process_exec",
        ts=START,
        host="host1",
        fields={},
        raw=[RawRef(target="linux", native_id="1")],
        normalizer="lab-ecs@9",
    )
    monkeypatch.setattr(sweep_module, "normalize_hits", lambda *_args, **_kwargs: ([linux], {}, []))
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="linux",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=1,
        total_relation="eq",
        returned=1,
        records=[{"_index": "linux", "_id": "1", "_source": {}}],
    ))
    contract = contract_from_types("linux", {"@timestamp": "date"}, role="host", os_family="linux")
    window = Window(start=START, end=START + timedelta(minutes=5))
    repo = _repo()
    sweep = Sweep(repo, None, "h1", window, {contract.target: contract})
    sweep.pack = [WindowsProcessRule()]

    sweep.run_partition(contract.target, contract, [], window, est=1)

    assert repo.rule_cells("h1")[0]["state"] == "not_applicable_no_events"


def test_sweep_cell_can_be_complete_only_after_all_windows_gates_pass(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    records = [_hit(10), _hit(11)]

    def execute(_client, intent, _contract):
        return SearchOutcome(
            target=intent.target,
            fingerprint="windows",
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=2,
            total_relation="eq",
            returned=2,
            records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    window = Window(start=START, end=START + timedelta(minutes=5))

    def run(site_facts):
        repo = _repo()
        sweep = Sweep(repo, None, "h1", window, {contract.target: contract}, site_facts=site_facts)
        sweep.pack = [WindowsProcessRule()]
        sweep._windows_inventory[contract.target] = {event_class.token}
        sweep._windows_inventory_reasons[contract.target] = []
        sweep.run_partition(contract.target, contract, [], window, est=2)
        return repo.rule_cells("h1")[0]

    complete = run(_site(tmp_path))
    unresolved = run(None)

    assert complete["state"] == "no_match_complete"
    assert unresolved["state"] == "evaluated_partial"
    assert unresolved["detail"]["reasons"] == [
        "collection not attested: Sysmon event id 1 on ws01.example.test"
    ]
