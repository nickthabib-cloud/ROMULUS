"""Raw-reference windows retain history, bounded citations and late evidence."""
from __future__ import annotations

import importlib
import inspect
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from romulus.hunt.publish import SourceCitationFetcher

START = datetime(2026, 1, 1, tzinfo=UTC)


def toy(*, distinct=False, threshold=3, seconds=10):
    base = importlib.import_module("romulus.detect.zeek_rate_state").ZeekWindowRule

    class Toy(base):
        id, title = "test.zeek_window", "Toy Zeek window"
        families = ("rpc_tx",)
        citation_fields = ("observer.name", "source.ip", "destination.ip", "toy.member", "toy.role")
        attack = ("T1210",)

        def select(self, event):
            if event.get("toy.ignore"):
                return None
            return ((event.get("observer.name"), event.get("source.ip"), event.get("destination.ip")),
                    event.get("toy.member"), event.get("toy.role"))

        def describe(self, event, total_refs, distinct_members, role):
            return ("high" if role == "success" else "lead",
                    f"{total_refs} attempt references for {distinct_members} members in the window.",
                    ("A toy observation, not an outcome assertion.",))

    Toy.distinct, Toy.threshold, Toy.seconds = distinct, threshold, seconds
    return Toy()


def event(identity, stamp=0, *, member="alice", role="attempt", source="10.0.0.1", sensor="sensor",
          refs=None, producer="zeek-ecs@2", family="rpc_tx"):
    values = {"observer.name": sensor, "source.ip": source, "destination.ip": "10.0.0.2",
              "toy.member": member, "toy.role": role, "unused.large": "x" * 1000}
    return TypedEvent(id=identity, family=family, ts=START + timedelta(seconds=stamp), host=sensor,
                      fields={key: fv(value, f"{identity}:native.{key}") for key, value in values.items()},
                      raw=[RawRef(target="native", native_id=value) for value in (refs if refs is not None else [identity])],
                      normalizer=producer)


def final_matches(rule, events):
    matches = [*rule.consume(events), *rule.finalize()]
    kept = {}
    for match in matches:
        if match.group_key not in kept or match.revision_reason:
            kept[match.group_key] = match
    return list(kept.values())


def test_one_event_counts_unique_raw_references_and_keeps_bounded_native_citations():
    rule = toy()
    try:
        row = event("canonical", refs=[f"copy-{n}" for n in range(12)])
        [match] = list(rule.consume([row]))
        assert "12 attempt references" in match.claim
        assert match.events[0].id == row.id and len(match.events[0].raw) <= 3
        assert "unused.large" not in match.events[0].fields
        assert COMPACT_CITATION_NOTE in match.events[0].caveats
        assert any("partial" in note.lower() and "citation" in note.lower() for note in match.notes)
        assert all(item.origin == row.fields[item.field].origin for item in match.predicate)
        assert not list(rule.finalize())
    finally:
        rule.release_state()


def test_duplicate_refs_in_same_event_or_other_event_never_count_twice():
    rule = toy()
    try:
        assert not final_matches(rule, [event("a", refs=["shared", "shared"]),
                                        event("b", 1, refs=["shared"]), event("c", 2, refs=["other"])])
        assert rule.rows.store().execute("SELECT SUM(weight) FROM history").fetchone()[0] == 2
    finally:
        rule.release_state()


def test_same_canonical_event_can_gain_refs_and_cross_threshold_without_duplicate_facts():
    rule = toy()
    try:
        assert not list(rule.consume([event("a", refs=["r1", "r2"])]))
        [match] = list(rule.consume([event("a", refs=["r2", "r3", "r1"])]))
        assert "3 attempt references" in match.claim
        assert not list(rule.consume([event("a", refs=["r3", "r1", "r2"])]))
        assert rule.rows.store().execute("SELECT COUNT(*) FROM history").fetchone()[0] == 1
        assert rule.rows.store().execute("SELECT COUNT(*) FROM raw_refs").fetchone()[0] == 3
    finally:
        rule.release_state()


def test_missing_refs_do_not_create_counts_and_other_producers_or_families_are_out_of_scope():
    rule = toy(threshold=1)
    try:
        assert not final_matches(rule, [event("no-refs", refs=[]), event("host", producer="windows-ecs@16"),
                                        event("suricata", producer="lab-ecs@1"), event("other", family="dns_query")])
        assert rule.missing_required == 1 and not rule.assures_negative
    finally:
        rule.release_state()


def test_distinct_members_are_not_raw_ref_weights():
    rule = toy(distinct=True)
    try:
        assert not list(rule.consume([event("a", refs=["r1", "r2", "r3", "r4"]), event("b", 1)]))
        assert not list(rule.consume([event("c", 2, member="bob")]))
        [match] = list(rule.consume([event("d", 3, member="carol")]))
        assert "7 attempt references for 3 members" in match.claim
    finally:
        rule.release_state()


@pytest.mark.parametrize("last,positive", [(10, True), (10.000001, False)])
def test_window_endpoints_are_inclusive(last, positive):
    rule = toy()
    try:
        assert bool(final_matches(rule, [event("a", 0), event("b", 5), event("c", last)])) is positive
    finally:
        rule.release_state()


def test_expiry_decrements_member_counts_without_forgetting_history():
    rule = toy(distinct=True)
    try:
        rows = [event("a", 0), event("b", 9), event("c", 10, member="bob"), event("d", 11, member="carol")]
        [match] = list(rule.consume(rows))
        assert "3 attempt references for 3 members" in match.claim
        assert rule.rows.store().execute("SELECT COUNT(*) FROM history").fetchone()[0] == 4
        assert rule.rows.store().execute("SELECT SUM(n) FROM members").fetchone()[0] == 3
    finally:
        rule.release_state()


def test_sensor_and_source_keys_have_independent_thresholds():
    rule = toy()
    try:
        rows = [event(f"{sensor}-{source}-{n}", n, sensor=sensor, source=source)
                for sensor in ("one", "two") for source in ("10.0.0.1", "10.0.0.3") for n in range(2)]
        assert not final_matches(rule, rows)
    finally:
        rule.release_state()


def test_success_does_not_count_as_an_attempt_and_promotes_existing_lead_immediately():
    rule = toy()
    try:
        lead = list(rule.consume([event("a", 0), event("b", 1), event("c", 2)]))
        [high] = list(rule.consume([event("success", 3, role="success", refs=["s1", "s2", "s3"])]))
        assert len(lead) == 1 and lead[0].proposed_lane == "lead"
        assert high.proposed_lane == "high" and high.group_key == lead[0].group_key and high.revision_reason
        assert "3 attempt references" in high.claim and "success" in {row.id for row in high.events}
        [revision] = list(rule.consume([event("more-success", 4, role="success"), event("d", 5)]))
        assert revision.proposed_lane == "high" and revision.group_key == high.group_key
        assert revision.bounded_revision and revision.revision_reason
        assert "4 attempt references" in revision.claim
        assert not list(rule.finalize())
    finally:
        rule.release_state()


def test_success_alone_or_before_unqualified_attempts_cannot_cross_threshold():
    rule = toy()
    try:
        assert not final_matches(rule, [event("s", 0, role="success", refs=["s1", "s2", "s3"]),
                                        event("a", 1), event("b", 2)])
    finally:
        rule.release_state()


@pytest.mark.parametrize("order", [(0, 8, 12, 16), (16, 12, 8, 0), (0, 8, 16, 12)])
def test_ordered_replay_finds_every_late_window(order):
    rule = toy()
    try:
        [match] = final_matches(rule, [event(str(n), n) for n in order])
        assert match.proposed_lane == "lead" and "3 attempt references" in match.claim
        assert inspect.isgenerator(rule.finalize())
    finally:
        rule.release_state()


def test_late_success_and_late_added_refs_are_replayed_without_changing_forward_window():
    rule = toy()
    try:
        assert not list(rule.consume([event("a", 0), event("b", 1), event("s", 3, role="success")]))
        assert not list(rule.consume([event("a", 0, refs=["a", "extra"])]))
        replay = list(rule.finalize())
        assert [match.proposed_lane for match in replay] == ["high"]
        match = replay[-1]
        assert match.proposed_lane == "high" and "3 attempt references" in match.claim
    finally:
        rule.release_state()


@pytest.mark.parametrize("success_first", [False, True])
def test_equal_timestamp_success_context_never_proves_a_following_success(success_first):
    rule = toy()
    try:
        attempts = [event("a", 1), event("b", 1), event("c", 1)]
        success = event("0-success", 1, role="success")
        result = final_matches(rule, [success, *attempts] if success_first else [*attempts, success])
        assert result[-1].proposed_lane == "lead"
    finally:
        rule.release_state()


def test_citations_use_actual_refs_and_standard_fetcher_without_fake_event_ids():
    rule = toy()
    try:
        rows = [event(str(n), n) for n in range(4)]
        rule.load = lambda ids: [row for row in rows if row.id in ids]
        match = list(rule.consume(rows))[-1]
        assert len(match.events) <= 3 and {row.id for row in match.events} <= {row.id for row in rows}
        sources = {ref.key: {"native": ref.native_id} for row in rows for ref in row.raw}
        SourceCitationFetcher(None).hydrate(match, sources)
        assert all(COMPACT_CITATION_NOTE not in row.caveats for row in match.events)
        assert match.raw_copies and set(match.raw_copies) <= set(sources)
    finally:
        rule.release_state()


def test_schema_refusal_is_named_partial_and_safe_to_finalize(tmp_path):
    rule = toy()
    rule.budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    rule.budget.plan(1)
    try:
        assert not final_matches(rule, [event("a", refs=["1", "2", "3"])])
        assert rule.capped and any("schema" in note.lower() for note in rule.limit_reasons())
        assert not rule.assures_negative
    finally:
        rule.release_state()


def test_history_refusal_keeps_previously_accepted_rows(tmp_path):
    rule = toy()
    rule.budget = StateBudget(tmp_path, disk_total=4 * 1024 * 1024, reserve=0)
    try:
        assert not list(rule.consume([event("a")]))
        rule.budget.force_full("test history cap", lambda _account: True)
        assert not list(rule.consume([event("b", 1)]))
        assert rule.rows.store().execute("SELECT COUNT(*) FROM history").fetchone()[0] == 1
        assert rule.capped and any("history" in note.lower() for note in rule.limit_reasons())
    finally:
        rule.release_state()


def test_derived_refusal_is_named_and_history_can_be_replayed_after_capacity_returns(monkeypatch):
    rule = toy()
    original = rule.rows.room
    try:
        monkeypatch.setattr(rule.rows, "room", lambda kind: kind != "derived" and original(kind))
        list(rule.consume([event("a"), event("b", 1), event("c", 2)]))
        assert any("derived" in note.lower() for note in rule.limit_reasons())
        assert rule.rows.store().execute("SELECT COUNT(*) FROM history").fetchone()[0] == 3
        monkeypatch.setattr(rule.rows, "room", original)
        [match] = list(rule.finalize())
        assert match.proposed_lane == "lead"
    finally:
        rule.release_state()


def test_fresh_replay_has_deterministic_group_claim_and_native_reference_sample():
    snapshots = []
    for _ in range(2):
        rule = toy()
        try:
            [match] = final_matches(rule, [event("s", 3, role="success"),
                                          event("c", 2), event("b", 1), event("a", 0)])
            snapshots.append((match.group_key, match.claim, match.proposed_lane,
                              [(row.id, [ref.key for ref in row.raw]) for row in match.events]))
        finally:
            rule.release_state()
    assert snapshots[0] == snapshots[1]


def test_live_expiry_does_not_delete_old_history_and_finalize_streams_it():
    rule = toy(threshold=3000, seconds=3)
    try:
        for n in range(2500):
            assert not list(rule.consume([event(str(n), n, member=str(n))]))
        db = rule.rows.store()
        assert db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 2500
        assert db.execute("SELECT COUNT(*) FROM raw_refs").fetchone()[0] == 2500
        assert db.execute("SELECT COUNT(*) FROM active").fetchone()[0] == 4
        assert not list(rule.finalize())
        assert db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 2500
    finally:
        rule.release_state()


def test_unresolvable_empty_native_references_do_not_create_counts():
    rule = toy(threshold=1)
    try:
        row = event("bad")
        row.raw = [RawRef(target="", native_id=""), RawRef(target="native", native_id="")]
        assert not final_matches(rule, [row])
        assert rule.missing_required == 1
    finally:
        rule.release_state()


def test_compact_citations_preserve_record_caveats_and_cannot_be_rewritten_by_loader():
    rule = toy(threshold=1)
    try:
        row = event("original")
        row.caveats = ["Recorded outcome is unavailable."]
        rule.load = lambda _ids: [row.model_copy(update={"outcome": "success", "host": "other"})]
        [match] = list(rule.consume([row]))
        assert match.events[0].outcome == row.outcome and match.events[0].host == row.host
        assert row.caveats[0] in match.events[0].caveats
    finally:
        rule.release_state()


def test_conflicting_facts_for_same_canonical_id_are_named_unresolved_without_replacing_history():
    rule = toy()
    try:
        assert not list(rule.consume([event("canonical", 0)]))
        assert not list(rule.consume([event("canonical", 1, refs=["new-ref"])]))
        assert any("conflicting" in note.lower() for note in rule.limit_reasons())
        assert rule.rows.store().execute("SELECT weight FROM history").fetchone()[0] == 1
    finally:
        rule.release_state()


def test_single_retained_multi_ref_attempt_can_publish_when_derived_allocation_is_refused(monkeypatch):
    rule = toy()
    original = rule.rows.room
    try:
        monkeypatch.setattr(rule.rows, "room", lambda kind: kind != "derived" and original(kind))
        [match] = list(rule.consume([event("canonical", refs=["r1", "r2", "r3"])]))
        assert "3 attempt references" in match.claim
        assert any("lower bound" in note.lower() for note in match.notes)
        assert rule.capped and len(match.events) == 1
    finally:
        rule.release_state()


def test_compact_reference_sample_prioritizes_the_native_source_of_predicate_fields():
    rule = toy()
    try:
        row = event("z-origin", refs=["a-copy", "b-copy", "c-copy", "z-origin"])
        [match] = list(rule.consume([row]))
        assert "z-origin" in {ref.native_id for ref in match.events[0].raw}
        assert len(match.events[0].raw) == 3
        assert all(item.origin.startswith("z-origin:") for item in match.predicate)
    finally:
        rule.release_state()
