"""Approval changes aggregation, while every observation remains a lead."""
from types import SimpleNamespace

import pytest

from romulus.decide.policy import decide
from romulus.detect.bounded import StateBudget
from tests.test_service_catalog import event, final, module, networks  # noqa: F401


@pytest.fixture
def rule():
    instance = module().ServiceCatalog()
    yield instance
    instance.close_spill()


@pytest.mark.parametrize("hosts", [1, 25])
def test_approved_entry_has_only_one_fleet_lead_with_exact_membership(rule, hosts):
    rule.site_facts = SimpleNamespace(approved_remote_access=("teamviewer",))
    rows = final(rule, [event("router.teamviewer.com", source=f"10.0.0.{i}", n=i) for i in range(1, hosts + 1)])
    assert len(rows) == 1
    [fleet] = rows
    assert fleet.group_key == "teamviewer|fleet"
    assert fleet.fleet_host_count == hosts == len(fleet.fleet_hosts)
    assert fleet.fleet_hosts_complete and fleet.aggregate_summary["source_count_complete"] == 1
    assert decide(fleet, "synthetic").lane == "lead"
    assert any("site-approved" in note and "teamviewer" in note for note in fleet.notes)
    assert len(fleet.events) <= 2
    if hosts > 2:
        assert any("citation" in note.casefold() and "partial" in note.casefold() for note in fleet.notes)


def test_suffix_approval_does_not_approve_sibling_or_other_entry(rule):
    rule.site_facts = SimpleNamespace(approved_remote_access=("gotoassist.com",))
    rows = final(rule, [event("a.gotoassist.com", n=1), event("a.fastsupport.com", n=2),
                        event("relay.teamviewer.com", n=3)])
    by_key = {row.group_key: row for row in rows}
    assert set(by_key) == {"goto|approved|fleet", "goto|source|10.0.0.1", "goto|fleet",
                           "teamviewer|source|10.0.0.1", "teamviewer|fleet"}
    assert any("gotoassist.com" in note for note in by_key["goto|approved|fleet"].notes)
    assert not any("site-approved" in note for note in by_key["goto|source|10.0.0.1"].notes)
    assert all(decide(row, "synthetic").lane == "lead" for row in rows)


def test_mixed_plural_names_split_approved_and_unapproved_membership(rule):
    rule.site_facts = SimpleNamespace(approved_remote_access=("ngrok-free.app",))
    rows = final(rule, [event(["approved.ngrok-free.app", "other.ngrok.io"], field="dns.question.names", n=1),
                        event("another.ngrok-free.app", source="10.0.0.2", n=2)])
    by_key = {row.group_key: row for row in rows}
    assert set(by_key) == {"ngrok|approved|fleet", "ngrok|source|10.0.0.1", "ngrok|fleet"}
    assert by_key["ngrok|approved|fleet"].fleet_host_count == 2
    assert by_key["ngrok|fleet"].fleet_hosts == (("10.0.0.1", ""),)


def test_approval_obeys_label_boundaries(rule):
    rule.site_facts = SimpleNamespace(approved_remote_access=("tenant.screenconnect.com",))
    rows = final(rule, [event("x.tenant.screenconnect.com", n=1),
                        event("nottenant.screenconnect.com", source="10.0.0.2", n=2)])
    assert {row.group_key for row in rows} == {
        "screenconnect|approved|fleet", "screenconnect|source|10.0.0.2", "screenconnect|fleet"}


def test_suffix_approval_does_not_cross_overlapping_catalog_entries():
    def item(slug, suffix):
        return {"id": slug, "name": slug, "category": "remote_access", "suffixes": [suffix],
                "attack": ["T1219.002"], "license": "CC0-1.0",
                "sources": [{"url": "https://example.org/docs", "license": "CC0-1.0"}]}
    catalog = module().Catalog({"schema": "romulus.network-services@1", "version": "synthetic",
                                "entries": [item("parent", "service.example"),
                                            item("child", "child.service.example")]})
    instance = module().ServiceCatalog(catalog)
    instance.site_facts = SimpleNamespace(approved_remote_access=("service.example",))
    try:
        rows = final(instance, [event("x.child.service.example")])
        assert {row.group_key for row in rows} == {
            "parent|approved|fleet", "child|source|10.0.0.1", "child|fleet"}
        child = next(row for row in rows if row.group_key == "child|fleet")
        assert not any("site-approved" in note for note in child.notes)
    finally:
        instance.close_spill()


def test_approved_presence_remains_one_partial_fleet_when_disk_refuses(rule, tmp_path):
    rule.site_facts = SimpleNamespace(approved_remote_access=("ngrok",))
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    [row] = final(rule, [event()])
    assert row.group_key == "ngrok|fleet" and decide(row, "synthetic").lane == "lead"
    assert not row.fleet_hosts_complete and rule.capped == 1
    assert row.fleet_host_count >= 1


def test_approved_oversized_citation_still_retains_a_reportable_fleet(rule):
    rule.site_facts = SimpleNamespace(approved_remote_access=("ngrok",))
    observed = event()
    observed.raw[0].native_id = "x" * 1_000_000
    [row] = final(rule, [observed])
    assert row.citation_unavailable and row.fleet_host_count == 1
    assert row.fleet_hosts == (("10.0.0.1", ""),)
    assert decide(row, "synthetic").lane == "lead"


@pytest.mark.parametrize("name", ["logmein.com", "api.logmeininc.com", "meetings.logmein.com"])
def test_shared_goto_collaboration_domains_are_not_remote_support(rule, name):
    assert final(rule, [event(name)]) == []


@pytest.mark.parametrize("name", ["gotoassist.com", "fastsupport.com", "helpme.net", "gotoassist.me",
                                  "gotoassist.at", "desktopstreaming.com", "logmeinrescue.com"])
def test_goto_support_domains_remain_leads(rule, name):
    assert {row.group_key for row in final(rule, [event(name)])} == {"goto|source|10.0.0.1", "goto|fleet"}
