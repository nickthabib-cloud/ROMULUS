"""Fleet publications agree with bounded citations and immutable report appendices."""
from datetime import timedelta

import pytest

from romulus.detect.windows_memory_events import ProcessImageTampering
from tests.test_candidate_revision import _match, _publish
from tests.test_sweep import _repo
from tests.test_windows_auth_round5 import publish
from tests.test_windows_b_round5 import native
from tests.windows_process_support import sysmon1


@pytest.mark.parametrize("revising", [False, True])
def test_ignored_fleet_duplicate_never_mutates_host_members_or_claim(revising):
    repo = _repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="duplicate-hosts", reason="checkpoint" if revising else "")
    match.fleet_host_count = 1
    match.fleet_hosts = (("first", event.id),)
    row = _publish(repo, match, event)
    before = repo.candidate(row["id"])
    match.fleet_hosts = (("later", event.id),)
    match.fleet_hosts_complete = True
    assert _publish(repo, match, event) is None
    assert repo.candidate(row["id"]) == before
    hosts, after = repo.candidate_hosts(row["id"])
    assert [item["host"] for item in hosts] == ["first"] and not after


def test_native_behavior_fleet_stored_citations_match_bounded_claim():
    repo, rule = _repo(), ProcessImageTampering()
    events = [native(25, {"Image": r"C:\Program Files\Vendor\app.exe", "Type": "Image is replaced"},
                     f"host-{number:04}") for number in range(120)]
    staged = {}
    rule.load = lambda ids: [staged[key] for key in ids if key in staged]
    for number, event in enumerate(events):
        event = event.model_copy(update={"ts": event.ts+timedelta(seconds=number)})
        matches = rule.consume([event])
        staged.update({item.id: item for item in rule.drain_staged()})
        for match in matches:
            publish(repo, rule, match)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert len(candidate["event_ids"]) <= 30
    assert f"{len(candidate['event_ids'])} of the 120 records are cited" in candidate["claim"]
    assert candidate["gate_results"]["_fleet_host_count"] == 120
    assert candidate["gate_results"]["_fleet_hosts_retained"] == 120
    rule.release_state()


def test_persisting_one_new_host_does_not_recount_every_existing_member():
    repo = _repo()
    event = sysmon1(image=r"C:\Windows\System32\example.exe", command="example.exe")
    match = _match([event], group_key="linear-hosts")
    match.fleet_host_count = 10000
    match.fleet_hosts = ((f"host-{n:05}", event.id) for n in range(10000))
    row = _publish(repo, match, event)
    steps = 0

    def progress():
        nonlocal steps
        steps += 100
        return 0

    with repo.engine.connect() as connection:
        db = connection.connection.driver_connection
        db.set_progress_handler(progress, 100)
        try:
            repo.save_candidate_hosts(row["id"], "h1", [("host-new", event.id)], expected_count=10001)
        finally:
            db.set_progress_handler(None, 0)
    assert steps < 5000
    assert repo.candidate(row["id"])["gate_results"]["_fleet_hosts_retained"] == 10001
