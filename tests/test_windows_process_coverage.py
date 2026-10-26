"""Coverage honesty for the Windows process rules.

ROMULUS never asserts absence: every W1a rule is positive-only, so no W1a rule ever writes `no_match_complete`.
Coverage cells still record what was searched and what was not — unattested or incomplete collection is stated in
the cell reasons — but that never becomes a complete negative.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.registry import WINDOWS_PROCESS_PLAYBOOKS
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL, lookup_event_class
from romulus.hunt.sweep import Sweep
from romulus.site import load_site_facts
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types

START = datetime(2026, 1, 2, tzinfo=UTC)


def _contract():
    return contract_from_types(
        "win-host",
        {"@timestamp": "date", "event.dataset": "keyword", "winlog.channel": "keyword",
         "winlog.provider_name": "keyword", "winlog.event_id": "long", "winlog.computer_name": "keyword",
         "winlog.record_id": "long", "winlog.event_data": "flattened"},
        role="host", hosts=("ws01.example.test",),
    )


def _hit(record_id: int, event_id: int, provider: str, channel: str):
    return {
        "_index": "logs-windows", "_id": f"w-{record_id}",
        "_source": {"@timestamp": "2026-01-02T00:05:00Z", "agent": {"type": "winlogbeat"},
                    "event": {"dataset": "windows.sysmon_operational"},
                    "winlog": {"channel": channel, "provider_name": provider, "event_id": event_id,
                               "computer_name": "WS01.example.test", "record_id": record_id, "event_data": {}}},
    }


def _sweep(tmp_path, rule, site_facts):
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=site_facts)
    sweep.pack = [rule]
    sysmon1 = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    event4688 = lookup_event_class("Security", SECURITY, 4688)
    sweep._windows_inventory[contract.target] = {sysmon1.token, event4688.token}
    sweep._windows_inventory_reasons[contract.target] = []
    records = [_hit(10, 1, SYSMON, SYSMON_CHANNEL), _hit(11, 4688, SECURITY, "Security")]
    return sweep, contract, records


def test_every_windows_process_rule_is_positive_only_with_a_reason():
    for cls in WINDOWS_PROCESS_PLAYBOOKS:
        assert cls.assures_negative is False, cls.id
        assert cls.positive_only_reason, cls.id
        # the reason must never point at another rule as its assurance
        assert cls.id not in cls.positive_only_reason


def test_unattested_collection_is_stated_in_the_cell_reasons(tmp_path):
    # Even positive-only, the coverage cell still records what collection was not attested — it just never claims a
    # complete negative. The lineage rule declares both process-creation classes, so both wants attestation.
    rule = LureAppSpawnsCodeRunner()
    sweep, contract, records = _sweep(tmp_path, rule, load_site_facts(tmp_path))  # no site file
    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, records, [])
    assert any("collection not attested" in reason for reason in reasons)


def test_incomplete_shipper_reason_is_carried_through(tmp_path):
    rule = LureAppSpawnsCodeRunner()
    sweep, contract, records = _sweep(tmp_path, rule, load_site_facts(tmp_path))
    reasons = sweep._windows_rule_reasons(
        contract.target, contract, rule, records, ["shipper gaps unresolved: winlog.record_id mapping is not numeric"],
    )
    assert "shipper gaps unresolved: winlog.record_id mapping is not numeric" in reasons
