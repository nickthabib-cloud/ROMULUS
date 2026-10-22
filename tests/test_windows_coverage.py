"""Windows coverage requires inventory, streaming continuity, and site collection attestations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.base import Playbook
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.evidence.windows import RecordIdContinuity
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL, lookup_event_class
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


def test_windows_coverage_gate_requires_inventory_continuity_and_matching_attestation(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    assert sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10)], []) == []
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


def test_sweep_cell_can_be_complete_only_after_all_windows_gates_pass(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    record = _hit(10)

    def execute(_client, intent, _contract):
        return SearchOutcome(
            target=intent.target,
            fingerprint="windows",
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=1,
            total_relation="eq",
            returned=1,
            records=[record],
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
        sweep.run_partition(contract.target, contract, [], window, est=1)
        return repo.rule_cells("h1")[0]

    complete = run(_site(tmp_path))
    unresolved = run(None)

    assert complete["state"] == "no_match_complete"
    assert unresolved["state"] == "evaluated_partial"
    assert unresolved["detail"]["reasons"] == [
        "collection not attested: Sysmon event id 1 on ws01.example.test"
    ]
