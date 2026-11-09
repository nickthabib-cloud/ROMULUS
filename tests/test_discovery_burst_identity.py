"""A post-access discovery burst outside a login session has one identity, whichever anchors reach it."""
from datetime import timedelta

from romulus.detect.context import PostAccessDiscovery
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.context import finalize_context
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.claim_citations import finding_problems
from tests.test_context_playbooks import T0, _seed_anchor, _seed_link

RULE = "context.post_access_discovery"


def proc(event_id, seconds, pid, ppid, argv, exe=None, host="web1", **fields):
    values = {"process.executable": exe or argv[0], "process.argv": list(argv), "process.pid": pid,
              "process.ppid": ppid, "process.uid": "0", "host.boot.id": "boot-1",
              **{name.replace("__", "."): value for name, value in fields.items()}}
    return TypedEvent(id=event_id, family="process_exec", ts=T0 + timedelta(seconds=seconds), host=host,
                      fields={name: fv(value, f"{event_id}:{name}") for name, value in values.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def lineage():
    """A daemon-started root lineage: a forked cron child (no exec of its own, pid 900) ran sh, then sudo, then a
    shell that ran a discovery burst of three classes."""
    return [proc("sh", 0, 910, 900, ["/bin/sh", "-c", "/opt/job.sh"]),
            proc("sudo", 1, 911, 910, ["/usr/bin/sudo", "-u", "root", "/bin/bash", "/opt/inner.sh"]),
            proc("bash", 2, 912, 911, ["/bin/bash", "/opt/inner.sh"])]


def burst(prefix="d", start=3, ppid=912):
    return [proc(f"{prefix}-whoami", start, 920, ppid, ["/usr/bin/whoami"]),
            proc(f"{prefix}-uname", start + 1, 921, ppid, ["/usr/bin/uname", "-a"]),
            proc(f"{prefix}-ss", start + 2, 922, ppid, ["/usr/bin/ss", "-tunap"])]


def repo_for(anchors):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    for anchor_id, records, strength in anchors:
        _seed_anchor(repo, "h1", anchor_id, "host.credential_material_access",
                     [proc(f"{anchor_id}-event", 0, 930, 912, ["/bin/cat", "/etc/shadow"])])
        _seed_link(repo, "h1", f"L-{anchor_id}", anchor_id, records, link_type="process_lineage", strength=strength)
    finalize_context(repo, "h1")
    found = [c for c in repo.candidates("h1") if c["rule_id"] == RULE and c["lane"] != "context"]
    for candidate in found:      # every finding cites what it states (counts, pids, times)
        cited = [TypedEvent.model_validate(row["event"]) for row in repo.citation_events("h1", candidate["event_ids"])]
        assert finding_problems(candidate["claim"], candidate["gate_results"]["_notes"], cited) == []
    return found


def test_two_anchors_reaching_one_burst_publish_one_finding_with_both_reaches():
    records = [*lineage(), *burst()]
    # the two reaches hold nearly the same records, as sibling anchors' lineage links do
    found = repo_for([("F-one", records, "observed"), ("F-two", records[1:], "observed")])
    assert len(found) == 1
    finding = found[0]
    assert {reach["anchor_id"] for reach in finding["gate_results"]["_context_reaches"]} == {"F-one", "F-two"}
    assert "2 anchors reached these records" in finding["claim"]
    assert "lin:900|" in finding["group_key"] and "F-" not in finding["group_key"]
    assert finding["lane"] == "high"


def test_identity_does_not_depend_on_which_anchor_reached_the_burst():
    records = [*lineage(), *burst()]
    one = repo_for([("F-one", records, "observed")])
    two = repo_for([("F-two", records, "observed")])
    assert [c["group_key"] for c in one] == [c["group_key"] for c in two]
    assert [c["id"] for c in one] == [c["id"] for c in two]


def test_finding_cites_the_lineage_between_its_root_and_the_commands():
    found = repo_for([("F-one", [*lineage(), *burst()], "observed")])
    finding = found[0]
    assert {"sh", "sudo", "bash"} <= set(finding["event_ids"])
    assert "parent chains reach pid(s) 900 " in finding["claim"] and "3 lineage record(s)" in finding["claim"]
    lineage_fields = {(p["field"], p["value"]) for p in finding["predicate_fields"] if p["field"] == "process.ppid"}
    assert {("process.ppid", 900), ("process.ppid", 911)} <= lineage_fields


def test_lane_is_the_highest_of_its_reaches():
    records = [*lineage(), *burst()]
    inferred_only = repo_for([("F-one", records, "inferred")])
    assert [c["lane"] for c in inferred_only] == ["lead"]
    mixed = repo_for([("F-one", records, "inferred"), ("F-two", records, "observed")])
    assert [c["lane"] for c in mixed] == ["high"]


def test_bursts_of_one_root_apart_by_more_than_the_gap_are_separate_and_name_only_their_reaches():
    gap = int(PostAccessDiscovery.BURST_GAP)
    early, late = burst("early", 3), burst("late", 3 + gap + 60)
    found = repo_for([("F-early", [*lineage(), *early], "observed"), ("F-late", [*lineage(), *late], "observed")])
    assert len(found) == 2
    by_reach = {frozenset(r["anchor_id"] for r in c["gate_results"]["_context_reaches"]): c for c in found}
    assert set(by_reach) == {frozenset({"F-early"}), frozenset({"F-late"})}
    assert not any("anchors reached these records" in c["claim"] for c in found)


def test_one_reach_is_never_split_by_time_or_by_a_broken_chain():
    """Splitting what one lineage reach saw could lower a burst's lane: a slow operator, or a subshell whose fork has
    no exec record, stays in one finding with every root named."""
    gap = int(PostAccessDiscovery.BURST_GAP)
    slow = [proc("w", 3, 920, 912, ["/usr/bin/whoami"]),
            proc("u", 3 + gap + 60, 921, 912, ["/usr/bin/uname", "-a"]),
            proc("s", 3 + 2 * gap + 120, 922, 5555, ["/usr/bin/ss", "-tunap"])]  # a subshell (pid 5555) never exec'd
    found = repo_for([("F-one", [*lineage(), *slow], "observed")])
    assert len(found) == 1 and found[0]["lane"] == "high"
    assert "reach pid(s) 900, 5555 " in found[0]["claim"]


def test_bursts_within_the_gap_stay_one():
    gap = int(PostAccessDiscovery.BURST_GAP)
    found = repo_for([("F-one", [*lineage(), *burst("a", 3), *burst("b", 3 + gap - 60)], "observed")])
    assert len(found) == 1


def test_different_roots_are_different_bursts():
    other = [proc("sh2", 0, 1910, 1900, ["/bin/sh", "-c", "/opt/other.sh"])]
    found = repo_for([("F-one", [*lineage(), *burst()], "observed"),
                      ("F-two", [*other, *burst("o", 5, ppid=1910)], "observed")])
    assert len(found) == 2
    assert {c["group_key"].split("|")[3] for c in found} == {"lin:900", "lin:1900"}


def test_session_bursts_keep_their_session_identity():
    records = [proc(f"s-{n}", n, 950 + n, 940, argv, process__session_id=7)
               for n, argv in enumerate([["/usr/bin/whoami"], ["/usr/bin/uname", "-a"], ["/usr/bin/ss", "-tunap"]])]
    found = repo_for([("F-one", records, "observed"), ("F-two", records, "observed")])
    assert len(found) == 1 and found[0]["group_key"] == "discovery|web1|boot-1|7"


def test_many_anchors_and_a_large_burst_stay_one_finding():
    commands = [["/usr/bin/whoami"], ["/usr/bin/uname", "-a"], ["/usr/bin/ss", "-tunap"], ["/usr/bin/id"]]
    big = [proc(f"big-{n}", 3 + n // 10, 5000 + n, 912, commands[n % len(commands)]) for n in range(2000)]
    records = [*lineage(), *big]
    anchors = [(f"F-{n:02d}", records[n:], "observed") for n in range(20)]
    found = repo_for(anchors)
    assert len(found) == 1
    assert len({r["anchor_id"] for r in found[0]["gate_results"]["_context_reaches"]}) == 20
    assert "2000 command(s)" in found[0]["claim"]
