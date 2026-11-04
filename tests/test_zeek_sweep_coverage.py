"""A Zeek record no normalizer reads costs only the rules reading the family it would have fed.

The sweep is called as it is, through its partition runner:
- rows of a Zeek log outside the catalog (modbus) feed no family a rule reads: a DNS rule beside them is searched in
  full on the DNS records it read, and one with only those rows has no data in scope; the rows are counted as not
  assessed, by target, and the report lists every skip with its count;
- rows of a catalogued log whose shipper cannot be told apart (a `zeek.dns` row with neither Security Onion's nor
  Elastic's markers) could hold DNS records: a DNS rule beside them is searched in part, a flow rule is not;
- a dataset no normalizer knows could hold anything, so every rule beside it is searched in part, as before.
"""
from datetime import timedelta

import pytest

from romulus.detect.base import Playbook
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests import test_sweep as ts
from tests.fixtures import zeek_factory as zf


class _DnsRule(Playbook):
    id = "test.dns"
    version = 1
    families = ("dns_query",)

    def match(self, event):
        self.evaluated += 1
        return []


class _FlowRule(Playbook):
    id = "test.flow"
    version = 1
    families = ("net_flow",)

    def match(self, event):
        self.evaluated += 1
        return []


def _suricata_dns() -> dict:
    return zf.previous_shapes()["malcolm-suricata-dns"][0]


def _zeek_unread(shape: str) -> dict:
    """A Zeek row of a log outside the catalog (modbus) as each shipper names it."""
    h = zf.WRITERS[shape](zf.UDP_DNS, f"zeek-modbus-{shape}")
    h["_source"]["event"]["dataset"] = "modbus" if shape == "malcolm" else "zeek.modbus"
    if shape == "elastic":
        h["_source"]["data_stream"]["dataset"] = "zeek.modbus"
    return h


def _ambiguous_dns() -> dict:
    """A zeek.dns row carrying neither Security Onion's nor Elastic's markers: its layout cannot be told."""
    h = zf.WRITERS["elastic"](zf.UDP_DNS, "zeek-dns-ambiguous")
    h["_source"]["event"]["dataset"] = "zeek.dns"
    h["_source"].pop("data_stream", None)
    h["_source"]["event"].pop("module", None)
    h["_source"].pop("fileset", None)
    return h


def _cells(monkeypatch, records, pack):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, records))
    contract = contract_from_types("net", {"@timestamp": "date", "event.dataset": "keyword"},
                                   role="network", os_family="unknown")
    window = Window(start=ts.START, end=ts.START + timedelta(minutes=5))
    repo = ts._repo()
    sweep = sw.Sweep(repo, ts.FakeClient(), "h1", window, {"net": contract})
    sweep.pack = pack
    sweep._profiles = {"net": {"role": "network", "datasets": {}}}
    sweep.run_partition("net", contract, [], window, est=1, any_of=[])
    return {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}, sweep


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion"])
def test_zeek_rows_of_a_log_outside_the_catalog_leave_a_rule_beside_them_searched_in_full(monkeypatch, shape):
    cells, sweep = _cells(monkeypatch, [_suricata_dns(), _zeek_unread(shape)], [_DnsRule()])
    cell = cells["test.dns"]
    assert cell["state"] == "no_match_complete" and cell["evaluated"] > 0
    assert not any("is not normalized" in reason for reason in cell["detail"]["reasons"])
    [(reason, count)] = sweep.stats["not_assessed_by_target"]["net"].items()
    assert "is not normalized" in reason and count == 1
    assert sweep.stats["skips"][reason] == 1 and not sweep.partial_reasons


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion"])
def test_zeek_rows_of_a_log_outside_the_catalog_alone_are_no_data_in_scope(monkeypatch, shape):
    cells, _sweep = _cells(monkeypatch, [_zeek_unread(shape)], [_DnsRule()])
    assert cells["test.dns"]["state"] == "not_applicable_no_events" and cells["test.dns"]["evaluated"] == 0


def test_an_unreadable_row_of_a_catalogued_log_poisons_only_the_rules_reading_its_family(monkeypatch):
    cells, sweep = _cells(monkeypatch, [_suricata_dns(), _ambiguous_dns()], [_DnsRule(), _FlowRule()])
    dns, flow = cells["test.dns"], cells["test.flow"]
    assert dns["state"] == "evaluated_partial"
    assert any("could hold dns_query records" in reason for reason in dns["detail"]["reasons"])
    assert flow["state"] == "not_applicable_no_events"
    assert not any("unsupported_records" in reason for reason in flow["detail"]["reasons"])
    assert sweep.partial_reasons


def test_an_unreadable_zeek_conn_row_is_an_error_of_the_flow_family_only(monkeypatch):
    """A conn row without a first-packet time is an error tagged with its dispatch token (`zeek:conn`, never cut at
    its colon): flow rules are searched in part, a DNS rule beside it in full."""
    broken = zf.malcolm(zf.Conn(), "zeek-conn-no-time")
    for path in ("@timestamp", "firstPacket", "timestamp"):
        broken["_source"].pop(path, None)
    cells, sweep = _cells(monkeypatch, [_suricata_dns(), broken], [_DnsRule(), _FlowRule()])
    assert sweep.stats["errors"] == 1
    assert cells["test.dns"]["state"] == "no_match_complete"
    flow = cells["test.flow"]
    assert flow["state"] == "evaluated_partial"
    assert any(reason.startswith("normalization_errors=1 in zeek:conn") and "feeds no known" not in reason
               for reason in flow["detail"]["reasons"])
    assert sw._error_tag("zeek:conn: zeek conn record has no first-packet time") == "zeek:conn"
    assert sw._error_tag("zeek: Malcolm Zeek record names no log at event.dataset") == "zeek"
    assert sw._error_tag("linux.audit: bad record") == "linux.audit"


def test_a_dataset_no_normalizer_knows_poisons_every_rule(monkeypatch):
    unknown = {"_id": "u1", "_index": "net", "_source": {"@timestamp": "2024-11-18T14:00:00Z",
                                                          "event": {"dataset": "vendor.thing"}}}
    cells, _sweep = _cells(monkeypatch, [_suricata_dns(), unknown], [_DnsRule(), _FlowRule()])
    assert cells["test.dns"]["state"] == "evaluated_partial"
    assert cells["test.flow"]["state"] == "evaluated_partial"
