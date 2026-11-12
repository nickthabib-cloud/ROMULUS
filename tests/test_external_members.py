"""Findings whose streamed members are outside addresses, not hosts: the evidence ranking stages them as `ip`
entities carrying the rule's tactics and keeps them out of the hunt's host population (so they never make a rule look
fleet-wide), and the reports and the web call them outside addresses."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import update

from romulus.hunt.rank import PASS_FINAL, compute_rank_pass
from romulus.report import markdown
from romulus.report.manifest import publish_revision
from romulus.store import schema as t
from tests.test_evidence_rank import START, _insert, _ranks, _repo, _row
from tests.test_report import _repo_with_finding
from tests.test_web import client  # noqa: F401

SERVICE = "net.long_inbound_session"


def _members(repo, candidate_id: str, addresses: list[str]) -> None:
    with repo.engine.begin() as connection:
        connection.execute(t.candidate_host.insert(), [
            {"candidate_id": candidate_id, "host": address, "first_event_id": ""} for address in addresses])


def _service_row(cid: str, inside: str, named: list[str], *, ts=START):
    row = _row(cid, SERVICE, ts=ts, entities=[["host", "arkime-01", "observer"], ["ip", inside, "dst"],
                                             *[["ip", address, "src"] for address in named]])
    row["gate_results"] = {**row["gate_results"], "_fleet_host_count": 0, "_fleet_member_kind": "external_address"}
    return row


def test_a_member_named_only_in_the_list_gets_the_rules_tactic_on_its_ip_entity():
    repo = _repo()
    members = [f"198.51.100.{n}" for n in range(1, 11)]
    _insert(repo, [_service_row("svc", "10.0.0.5", members[:2])])
    _members(repo, "svc", members)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    findings, entities = _ranks(repo)
    attacker = members[6]                                    # member #7: in the list, not in the finding's entities
    assert ("ip", attacker) in entities
    assert "initial-access" in entities[("ip", attacker)]["tactics"]
    assert entities[("ip", attacker)]["rules"] == 1 and entities[("ip", attacker)]["findings"] == 1
    # the finding itself is ranked on the endpoints it names, not on its thousand members
    assert findings["svc"]["entity"] in {"10.0.0.5", *members[:2]}


def test_outside_members_never_join_the_host_population_or_a_rules_fleet_spread():
    repo = _repo()
    rows = [_row(f"h{n}", "r.other", host=f"host-{n}", ts=START + timedelta(hours=n % 7)) for n in range(8)]
    services = [_service_row(f"svc{k}", f"10.0.0.{k + 5}", [], ts=START + timedelta(hours=k * 3)) for k in range(3)]
    _insert(repo, rows + services)
    for k in range(3):
        _members(repo, f"svc{k}", [f"198.51.{100 + k}.{n}" for n in range(1, 251)])
    summary = compute_rank_pass(repo, "h1", PASS_FINAL)
    # the 8 hosts and the 3 internal servers; the 750 outside addresses are not hosts
    assert summary["hunt_hosts"] == 11
    assert SERVICE not in {item["rule_id"] for item in summary["fleet_recurring_rules"]}
    findings, entities = _ranks(repo)
    assert not any("fleet" in reason for reason in findings["svc0"]["reasons"])
    assert ("ip", "198.51.102.250") in entities and ("host", "198.51.102.250") not in entities


def test_host_members_still_count_as_the_fleet():
    repo = _repo()
    _insert(repo, [_row("fleet", "r.fleet", host="h0")])
    with repo.engine.begin() as connection:
        connection.execute(update(t.candidate).where(t.candidate.c.id == "fleet").values(
            gate_results={"observation": "pass", "_fleet_host_count": 5}))
    _members(repo, "fleet", [f"h{n}" for n in range(5)])
    assert compute_rank_pass(repo, "h1", PASS_FINAL)["hunt_hosts"] == 5


def test_reports_and_the_web_call_outside_members_outside_addresses(tmp_path):
    repo, candidate = _repo_with_finding()
    with repo.engine.begin() as connection:
        gates = connection.execute(t.candidate.select().where(t.candidate.c.id == candidate)).mappings().one()[
            "gate_results"]
        connection.execute(update(t.candidate).where(t.candidate.c.id == candidate).values(
            gate_results={**gates, "_fleet_member_kind": "external_address"}))
    repo.save_candidate_hosts(candidate, "h1", [("198.51.100.7", ""), ("203.0.113.66", "")], expected_count=2)
    manifest = publish_revision(repo, "h1", "test")
    [finding] = manifest["findings"]
    assert finding["fleet_member_kind"] == "external_address"
    text = "".join(markdown.iter_render(manifest, host_rows=lambda ref: repo.report_hosts("h1", ref["sha256"])))
    assert "2 of 2 outside addresses retained" in text and "| Outside address | First recorded event ID |" in text
    assert "reporting hosts" not in text


def test_publication_persists_the_member_kind():
    from tests.test_candidate_revision import _match, _publish
    from tests.test_sweep import _repo as sweep_repo
    from tests.windows_process_support import sysmon1
    repo = sweep_repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="outside-members")
    match.fleet_host_count, match.fleet_member_kind = 2, "external_address"
    match.fleet_hosts = iter([("198.51.100.7", ""), ("203.0.113.66", "")])
    candidate = _publish(repo, match, event)
    gates = repo.candidate(candidate["id"])["gate_results"]
    assert gates["_fleet_member_kind"] == "external_address" and gates["_fleet_host_count"] == 2


def test_the_finding_page_lists_outside_addresses(client, tmp_path):  # noqa: F811
    from romulus.config import Settings
    from romulus.hunt import run as hunt_run
    from tests.test_web import _login
    browser, password, cid = client
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    with repo.engine.begin() as connection:
        gates = connection.execute(t.candidate.select().where(t.candidate.c.id == cid)).mappings().one()[
            "gate_results"]
        connection.execute(update(t.candidate).where(t.candidate.c.id == cid).values(
            gate_results={**gates, "_fleet_member_kind": "external_address"}))
    repo.save_candidate_hosts(cid, "h1", [("203.0.113.66", "")])
    _login(browser, password)
    page = browser.get(f"/findings/{cid}")
    assert page.status_code == 200
    assert "Outside addresses in this finding" in page.text and "Hosts in this finding" not in page.text
