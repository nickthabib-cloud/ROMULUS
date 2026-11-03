"""A sweep over Zeek rows of a log no normalizer reads yet never searches a rule in full.

The sweep counts every record whose skip names an unread dataset as a record no rule evaluated, which keeps every
rule's search over that partition partial. Zeek rows of logs outside the catalog must keep that skip: a partition
holding Zeek kerberos rows beside Suricata dns records is searched in part for a DNS rule, never in full, and one
holding only Zeek kerberos rows is never "no data in scope". The sweep is called as it is, through its partition
runner.
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


def _suricata_dns() -> dict:
    return zf.previous_shapes()["malcolm-suricata-dns"][0]


def _zeek_unread(shape: str) -> dict:
    """A Zeek row of a log outside the catalog (kerberos) as each shipper names it."""
    h = zf.WRITERS[shape](zf.UDP_DNS, f"zeek-kerberos-{shape}")
    h["_source"]["event"]["dataset"] = "kerberos" if shape == "malcolm" else "zeek.kerberos"
    if shape == "elastic":
        h["_source"]["data_stream"]["dataset"] = "zeek.kerberos"
    return h


def _cell(monkeypatch, records):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, records))
    contract = contract_from_types("net", {"@timestamp": "date", "event.dataset": "keyword"},
                                   role="network", os_family="unknown")
    window = Window(start=ts.START, end=ts.START + timedelta(minutes=5))
    repo = ts._repo()
    sweep = sw.Sweep(repo, ts.FakeClient(), "h1", window, {"net": contract})
    sweep.pack = [_DnsRule()]
    sweep._profiles = {"net": {"role": "network", "datasets": {}}}
    sweep.run_partition("net", contract, [], window, est=1, any_of=[])
    [cell] = repo.rule_cells("h1")
    return cell


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion"])
def test_zeek_rows_of_an_unread_log_keep_a_rule_beside_them_searched_in_part(monkeypatch, shape):
    cell = _cell(monkeypatch, [_suricata_dns(), _zeek_unread(shape)])
    assert cell["state"] == "evaluated_partial" and cell["evaluated"] > 0
    assert any("is not normalized" in reason for reason in cell["detail"]["reasons"])


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion"])
def test_zeek_rows_of_an_unread_log_alone_are_never_no_data_in_scope(monkeypatch, shape):
    cell = _cell(monkeypatch, [_zeek_unread(shape)])
    assert cell["state"] == "evaluated_partial" and cell["evaluated"] == 0
