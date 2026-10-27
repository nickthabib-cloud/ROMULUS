"""Late Windows account and ticket context keeps raw citations and one candidate identity."""
from romulus.detect.windows_correlations import CreatedThenPrivileged, KerberosTgtContext
from romulus.evidence.typed import fv
from tests.windows_event_support import event, run

SID = "S-1-5-21-1-2-3-1100"

def creation(offset=0):
    return event("account_change", 4720, offset=offset, native=f"created-{offset}", host="dc01", **{
        "account.group_id": SID, "account.name": "alice"})

def membership(offset=60, *, sid=SID, group="S-1-5-32-544"):
    return event("account_change", 4732, offset=offset, native=f"member-{offset}", host="ws01", **{
        "account.member_id": sid, "account.group_id": group})


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


def ticket(code, offset=0, *, principal="alice@example.test", ip="203.0.113.8"):
    return event("auth", code, offset=offset, native=f"ticket-{code}-{offset}", host="dc01", **{
        "account.name": principal, "account.domain": "example.test", "source.ip": ip,
        "auth.service_name": "fileserver$", "auth.encryption_type": 0x12})


def test_service_ticket_context_gap_is_a_caveated_lead_after_full_replay():
    rule = KerberosTgtContext()
    service = ticket(4769, 60)
    assert not rule.consume([service])
    matches = list(rule.finalize())
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "unresolved TGT context" in matches[0].claim
    assert any("cached" in note for note in matches[0].notes)


def test_prior_tgt_on_another_dc_suppresses_only_the_context_gap_regardless_of_arrival_order():
    tgt, service = ticket(4768), ticket(4769, 60)
    tgt.fields["account.name"] = fv("alice", "test")
    tgt.host = "dc02"
    assert not run(KerberosTgtContext(), [[service], [tgt]])
    for invalid in (ticket(4768, 90), ticket(4768, principal="other@example.test"), ticket(4768, ip="203.0.113.9")):
        assert run(KerberosTgtContext(), [invalid, service])


def test_context_resolution_after_a_published_gap_revises_the_same_id():
    rule = KerberosTgtContext()
    rule.consume([ticket(4769, 60)])
    [before] = list(rule.finalize())
    rule.consume([ticket(4768)])
    after = list(rule.finalize())
    assert len(after) == 1 and after[0].group_key == before.group_key
    assert after[0].revision_reason and "companion" in after[0].claim


def test_later_ticket_companion_never_overwrites_an_earlier_tickets_context_gap():
    matches = run(KerberosTgtContext(), [ticket(4769, 60), ticket(4768, 120), ticket(4769, 180)])
    assert len(matches) == 1 and "unresolved TGT context" in matches[0].claim
    assert matches[0].events[0].id == ticket(4769, 60).id
