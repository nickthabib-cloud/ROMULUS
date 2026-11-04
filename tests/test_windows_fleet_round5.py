"""Fleet membership is durable, bounded on each page, and visible in finding details."""
import pytest

from romulus.config import Settings
from romulus.hunt import run as hunt_run
from tests.test_candidate_revision import _match, _publish
from tests.test_sweep import _repo
from tests.test_web import _login, client  # noqa: F401
from tests.windows_process_support import sysmon1


def test_fleet_host_stream_persists_all_hosts_in_sorted_bounded_pages():
    repo = _repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="fleet-test")
    match.fleet_host_count = 251
    match.fleet_hosts = ((f"host-{number:03}", f"record-{number}") for number in range(250, -1, -1))
    candidate = _publish(repo, match, event)
    after, hosts = "", []
    while True:
        page, after = repo.candidate_hosts(candidate["id"], after=after)
        assert 0 < len(page) <= 50
        hosts.extend(row["host"] for row in page)
        if not after:
            break
    assert hosts == [f"host-{number:03}" for number in range(251)]
    assert repo.candidate(candidate["id"])["gate_results"]["_fleet_host_count"] == 251
    repo.save_candidate_hosts(candidate["id"], "h1", [("host-250", "later-record")])
    page, _ = repo.candidate_hosts(candidate["id"], after="host-249")
    assert page[0]["first_event_id"] == "record-250"
    repo.save_candidate_hosts(candidate["id"], "h1", [("host-001", "record-1")], replace=True)
    page, after = repo.candidate_hosts(candidate["id"])
    assert len(page) == 1 and page[0]["host"] == "host-001" and not after


def test_finding_detail_pages_every_fleet_host_and_escapes_names(client, tmp_path):  # noqa: F811
    browser, password, cid = client
    # The app and helper open the same migrated SQLite database.
    settings = Settings(home=tmp_path)
    repo = hunt_run.open_repo(settings)
    repo.save_candidate_hosts(cid, "h1", ((f"host-{n:03}", f"event-{n}") for n in range(121)))
    repo.save_candidate_hosts(cid, "h1", [("<host>", "native")])
    _login(browser, password)
    first = browser.get(f"/findings/{cid}")
    assert first.status_code == 200
    assert "&lt;host&gt;" in first.text and "Next host page" in first.text
    assert "host-120" not in first.text
    last = browser.get(f"/findings/{cid}", params={"host_after": "host-099"})
    assert "host-120" in last.text and "First host page" in last.text


@pytest.mark.parametrize("failure", ["raises", "short"])
def test_incomplete_host_stream_retains_the_positive_with_an_honest_list_claim(failure):
    repo = _repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="partial-fleet", claim="All 101 host names are retained in the paged host list.")
    match.fleet_host_count, match.fleet_hosts_complete = 101, True
    def members():
        for number in range(100):
            yield f"host-{number:03}", f"event-{number}"
        if failure == "raises":
            raise LookupError("injected member read failure")
    match.fleet_hosts = members()
    candidate = _publish(repo, match, event)
    [stored] = repo.candidates("h1")
    assert candidate["claim"] == stored["claim"]
    assert stored["lane"] == "high"
    assert "All 101" not in stored["claim"] and "100 of 101" in stored["claim"]
    assert not stored["gate_results"]["_fleet_hosts_complete"]
    assert stored["gate_results"]["_fleet_hosts_retained"] == 100


def test_host_write_lease_rejection_rolls_back_candidate_and_members_together(monkeypatch):
    repo = _repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="fenced-fleet")
    match.fleet_host_count, match.fleet_hosts_complete = 1, True
    match.fleet_hosts = (("host", event.id),)
    original, calls = repo._fence_lease, []
    def fence(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("injected lost lease")
        return original(*args, **kwargs)
    monkeypatch.setattr(repo, "_fence_lease", fence)
    with pytest.raises(RuntimeError, match="lost lease"):
        _publish(repo, match, event)
    assert not repo.candidates("h1")
