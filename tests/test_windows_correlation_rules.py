"""Native account sequences cite positively recorded actions and retain revision identity."""
from romulus.detect.windows_correlations import CreatedThenPrivileged
from tests.test_windows_c_burst_review import native_event
from tests.windows_process_support import run

SID = "S-1-5-21-1-2-3-1100"


def creation(offset=0):
    return native_event(4720, {"TargetSid": SID, "TargetUserName": "alice", "TargetDomainName": "EXAMPLE"},
                        offset=offset, host="dc01.example.test")


def membership(offset=60, *, sid=SID, group="S-1-5-32-544"):
    return native_event(4732, {"MemberSid": sid, "TargetSid": group, "TargetUserName": "Administrators",
                               "TargetDomainName": "BUILTIN"}, offset=offset)


def test_created_then_privileged_both_arrival_orders_cite_both_recorded_actions():
    assert CreatedThenPrivileged.lane == CreatedThenPrivileged.severity == "high"
    a, b = creation(), membership()
    first = run(CreatedThenPrivileged(), [[a], [b]])
    late = run(CreatedThenPrivileged(), [[b], [a]])
    assert len(first) == len(late) == 1
    assert first[0].claim == late[0].claim and first[0].group_key == late[0].group_key
    assert {item.id for item in first[0].events} == {a.id, b.id}
    assert first[0].proposed_lane == "high"


def test_created_join_never_uses_actor_name_or_later_creation():
    assert not run(CreatedThenPrivileged(), [membership(), creation(90)])
    assert not run(CreatedThenPrivileged(), [creation(), membership(sid="S-1-5-21-9-9-9-1100")])
    assert not run(CreatedThenPrivileged(), [creation(), membership(group="S-1-5-21-1-2-3-513")])
    assert not run(CreatedThenPrivileged(), [creation(), membership(offset=90000)])


def test_late_creation_context_revises_same_membership_candidate_and_keeps_raw():
    rule = CreatedThenPrivileged()
    old, newer, added = creation(), creation(30), membership()
    out = []
    for item in (old, added, newer):
        rule.bind_raw({item.raw[0].key: {"marker": item.id}})
        out.extend(rule.consume([item]))
    final = list(rule.finalize())
    assert len(out) == len(final) == 1
    assert out[0].group_key == final[0].group_key and final[0].revision_reason
    assert {item.id for item in final[0].events} == {newer.id, added.id}
    assert all(ref.key in final[0].raw_copies for item in final[0].events for ref in item.raw)
    rule.release_state()


def test_weak_remote_access_group_is_a_lead_even_after_recent_creation():
    [match] = run(CreatedThenPrivileged(), [creation(), membership(group="S-1-5-32-555")])
    assert match.proposed_lane == "lead"
