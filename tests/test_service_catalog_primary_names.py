"""Primary control, storage, callback and paste domains remain presence leads."""
import pytest

from tests.test_service_catalog import event, final, module, networks  # noqa: F401


@pytest.fixture
def rule():
    instance = module().ServiceCatalog()
    yield instance
    instance.close_spill()


@pytest.mark.parametrize("name,entry", [
    ("connect.ngrok-agent.com", "ngrok"),
    *[(f"tunnel.{region}.ngrok.com", "ngrok") for region in ("us", "eu", "ap", "au", "sa", "jp", "in")],
    ("g.api.mega.co.nz", "mega"), ("gfs204n210.userstorage.mega.co.nz", "mega"),
    ("token.dnslog.cn", "dnslog-cn"), ("token.ceye.io", "ceye"),
    ("pastebin.com", "pastebin"), ("paste.ee", "paste-ee"), ("hastebin.com", "hastebin"),
])
def test_primary_service_names_are_sourced_presence_leads(rule, name, entry):
    rows = final(rule, [event(name, field="tls.client.server_name")])
    assert {row.group_key for row in rows} == {f"{entry}|source|10.0.0.1", f"{entry}|fleet"}
    assert all(row.proposed_lane == "lead" for row in rows)
    assert all("observed" in row.claim for row in rows)
    item = rule.catalog.entries[entry]
    assert all(source["url"].startswith("https://") and source["license"] for source in item["sources"])


@pytest.mark.parametrize("name", ["ngrok.com", "api.ngrok.com", "mega.co.nz", "userstorage.mega.co.nz.evil.test",
                                  "notpastebin.com", "dnslog.cn.evil.test", "ceye.io.evil.test"])
def test_primary_names_keep_domain_boundaries(rule, name):
    assert final(rule, [event(name)]) == []
