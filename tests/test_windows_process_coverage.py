"""Coverage honesty for the negative-capable Windows process rules: a complete negative needs inventory, shipper
completeness and attested collection; the positive-only rules never claim one."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_remote import RemoteExecutionParent
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


def _both_attested_site(tmp_path):
    path = tmp_path / "site" / "collection.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        "      event_ids: [1]\n"
        "    security_4688_command_line: true\n"
        "    audit_policy:\n"
        '      "Process Creation": success\n',
        encoding="utf-8",
    )
    return load_site_facts(tmp_path)


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


def test_lineage_rule_is_negative_capable_only_when_both_collectors_are_attested(tmp_path):
    rule = LureAppSpawnsCodeRunner()
    assert rule.assures_negative is True
    sweep, contract, records = _sweep(tmp_path, rule, _both_attested_site(tmp_path))
    # attested: no coverage reason blocks a complete negative
    assert sweep._windows_rule_reasons(contract.target, contract, rule, records, []) == []


def test_lineage_rule_unattested_collection_is_partial_not_a_negative(tmp_path):
    rule = LureAppSpawnsCodeRunner()
    sweep, contract, records = _sweep(tmp_path, rule, load_site_facts(tmp_path))  # no site file
    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, records, [])
    assert any("collection not attested" in reason for reason in reasons)


def test_lineage_rule_completeness_unknown_is_carried_through(tmp_path):
    rule = RemoteExecutionParent()
    assert rule.assures_negative is True
    sweep, contract, records = _sweep(tmp_path, rule, _both_attested_site(tmp_path))
    reasons = sweep._windows_rule_reasons(
        contract.target, contract, rule, records, ["shipper gaps unresolved: winlog.record_id mapping is not numeric"],
    )
    assert "shipper gaps unresolved: winlog.record_id mapping is not numeric" in reasons


def test_positive_only_rules_declare_a_reason_and_never_assure_negatives():
    from romulus.detect.registry import WINDOWS_PROCESS_PLAYBOOKS
    for cls in WINDOWS_PROCESS_PLAYBOOKS:
        if cls.assures_negative:
            # negative-capable rules read images only, never the command line
            assert cls.reads_command_line is False, cls.id
        else:
            assert cls.positive_only_reason, cls.id
            # the reason must not point at another rule as its assurance
            assert cls.id not in cls.positive_only_reason
