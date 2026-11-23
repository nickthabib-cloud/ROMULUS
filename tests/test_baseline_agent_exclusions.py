"""Records the AI agent's findings cite leave baseline history without a gap.

The agent runs after the deterministic finish has written the hunt's segments and released its window material. Its
findings' cited keys join the hunt's exclusion ledger, and every overlapping segment the change touches is replaced by
one derived from its own rows less those keys: the same hours, scope hours and event hours, so cover stays continuous
and the derived history equals what an uninterrupted run that cited the keys from the start would have written.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.hunt import run as hunt_run
from romulus.hunt.baseline_writer import apply_exclusion_changes, refresh_cited_exclusions
from romulus.store.repo import Repo
from tests.test_baseline_held_history import (
    LATER_IMPLANT,
    ROUTINE,
    SWEEP_IMPLANT,
    _finish_run,
    _history,
    _later_snapshot,
    _reference,
    _window,
)
from tests.test_baseline_hunt_writer import _event, _repo
from tests.test_baseline_lookback import FakeHistory
from tests.test_baseline_writer_hours import SPEC, START, H


def _agent_finding(repo: Repo, events, *, finding_id: str = "agent-1", hunt_id: str = "hunt-a") -> None:
    """An admitted AI finding citing typed records, stored as the agent's admission stores it."""
    repo.save_evidence(hunt_id, list(events), {event.raw[0].key: {"event": event.id} for event in events}, None)
    repo.save_candidate({
        "id": finding_id, "hunt_id": hunt_id, "rule_id": "agent.finding", "rule_version": "1",
        "claim": "AI-proposed finding", "claim_type": "observed_action", "event_ids": [event.id for event in events],
        "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": events[0].ts, "severity": "medium",
        "confidence": "low", "lane": "lead", "priority": 0.25, "priority_reasons": [], "gate_results": {},
        "benign_alternatives": [], "next_checks": [], "group_key": finding_id, "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None, "provenance": "agent", "agent_hypothesis_id": None,
    })


def _finished_with_agent_pending(extra=()) -> Repo:
    """A complete hunt whose sweep cited implant A and which wrote its history; implant B is still in it."""
    repo = _repo()
    _window(repo, extra)
    assert _finish_run(repo)["execution_state"] == "completed_within_scope"
    counted = {name for row in _history(repo) for name, _count in row[-1]}
    assert "/tmp/.x/implant-b" in counted and "/tmp/.x/implant-a" not in counted
    assert repo.baseline_window_retention("hunt-a") is None        # the material is gone
    return repo


def _agent_done(repo: Repo, status: str = "completed") -> dict:
    return hunt_run._with_agent_result({"hunt_id": "hunt-a"}, repo, {"status": status})


def test_a_key_an_ai_finding_cites_leaves_history_with_no_gap():
    reference = _reference()              # implant B cited by a deterministic stage from the start
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])

    result = _agent_done(repo)

    summary = result["baseline_exclusions"]
    assert summary["status"] == "complete" and summary["derived"] == summary["stale"] == len(reference)
    assert summary["rebuilt_from_source"] == 0
    assert _history(repo) == reference
    assert repo.latest_audit("hunt-a", hunt_run.AGENT_EXCLUSIONS_ACTION)["detail"] == summary


def test_cover_is_continuous_across_the_derivation():
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    _agent_done(repo)

    coverage = _later_snapshot(repo)
    assert coverage["segment_ids"] and coverage["gaps"] == [] and coverage["effective_hours"] == 2
    derived = {row["id"] for row in repo.baseline_segments(statuses=["active"])}
    assert set(coverage["segment_ids"]) == derived
    # the derived segments keep the hours, scope hours and event hours of the ones they replace
    replaced = repo.baseline_segments(statuses=["stale"])
    assert [(row["start"], row["end"], row["events_total"], row["first_event_hour"]) for row in replaced] == [
        (row["start"], row["end"], row["events_total"], row["first_event_hour"])
        for row in repo.baseline_segments(statuses=["active"])]
    for old, new in zip(replaced, repo.baseline_segments(statuses=["active"]), strict=True):
        hours = lambda segment_id: [(row["scope"], row["hour"], row["events"])
                                    for row in repo.baseline_scope_hours(segment_id)]
        events = lambda segment_id: [(row["hour"], row["events"])
                                     for row in repo.baseline_segment_event_hours(segment_id)]
        assert hours(old["id"]) == hours(new["id"]) and events(old["id"]) == events(new["id"])
        assert set(new["excluded_keys"]) > set(old["excluded_keys"])


def test_the_refresh_after_a_resumed_agent_is_idempotent():
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    _agent_done(repo)
    history = _history(repo)
    segments = repo.baseline_segments()

    again = _agent_done(repo)["baseline_exclusions"]

    assert again["status"] == "complete" and again["derived"] == again["stale"] == 0
    assert _history(repo) == history and repo.baseline_segments() == segments


def test_an_agent_that_failed_still_takes_what_it_stored_out_of_history():
    reference = _reference()
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])

    _agent_done(repo, status="failed")

    assert _history(repo) == reference


def test_a_refresh_that_fails_leaves_the_ledger_and_history_as_they_were(monkeypatch):
    repo = _finished_with_agent_pending()
    history = _history(repo)
    ledger = repo.baseline_exclusion_keys(site="site-a", target="host-index", spec_id=SPEC.id,
                                          spec_version=SPEC.version, key_version=SPEC.key_version,
                                          start=START, end=START + 2 * H)
    _agent_finding(repo, [LATER_IMPLANT])

    def unavailable(*_args, **_kwargs):
        raise OSError("store unavailable")

    monkeypatch.setattr(Repo, "replace_baseline_hunt_exclusions", unavailable)
    result = _agent_done(repo)
    monkeypatch.undo()

    assert result["baseline_exclusions"]["status"] == "failed"
    assert "store unavailable" in result["baseline_exclusions"]["reason"]
    assert result["ai_agent"] == {"status": "completed"}
    assert _history(repo) == history
    assert repo.baseline_exclusion_keys(site="site-a", target="host-index", spec_id=SPEC.id,
                                        spec_version=SPEC.version, key_version=SPEC.key_version,
                                        start=START, end=START + 2 * H) == ledger
    assert repo.latest_audit("hunt-a", hunt_run.AGENT_EXCLUSIONS_ACTION)["detail"]["status"] == "failed"
    # the next agent finish (or resume) tries again and succeeds
    assert _agent_done(repo)["baseline_exclusions"]["derived"] >= 1


class _Killed(BaseException):
    """The worker dying between the derived rows and their publication."""


def test_a_kill_between_derivation_and_publication_leaves_the_old_segment_in_cover_never_neither(monkeypatch):
    reference = _reference()
    repo = _finished_with_agent_pending()
    old = _history(repo)
    _agent_finding(repo, [LATER_IMPLANT])

    def killed(*_args, **_kwargs):
        raise _Killed()

    monkeypatch.setattr(Repo, "publish_derived_baseline_segment", killed)
    with pytest.raises(_Killed):
        refresh_cited_exclusions(repo, "hunt-a")
    monkeypatch.undo()

    # the replaced segment is still the cover (never neither); its replacement is an unpublished build
    assert _history(repo) == old
    assert repo.baseline_segments(statuses=["building"])
    assert _later_snapshot(repo)["effective_hours"] == 2

    # the next refresh reclaims its own build and publishes it, retiring the old one in the same transaction
    summary = refresh_cited_exclusions(repo, "hunt-a")
    assert summary["derived"] >= 1 and _history(repo) == reference
    assert repo.baseline_segments(statuses=["building"]) == []


def test_the_publication_retires_the_old_segment_in_the_same_transaction():
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    seen: list[set[str]] = []
    real = Repo.publish_derived_baseline_segment

    def observed(self, segment_id, **kwargs):
        seen.append({row["id"] for row in self.baseline_segments(statuses=["active"])})
        out = real(self, segment_id, **kwargs)
        seen.append({row["id"] for row in self.baseline_segments(statuses=["active"])})
        return out

    Repo.publish_derived_baseline_segment = observed
    try:
        refresh_cited_exclusions(repo, "hunt-a")
    finally:
        Repo.publish_derived_baseline_segment = real

    before, after = seen[0], seen[-1]
    # exactly one generation is active on each side of the publication: never both, never neither
    assert len(before) == len(after) and not before & after


def test_a_union_that_dropped_a_key_falls_back_to_retiring_and_names_it():
    repo = _finished_with_agent_pending()
    # another hunt over these hours whose ledger is the only one citing implant B, while this hunt's ledger no
    # longer cites implant A: the union no longer holds a key the segments excluded
    repo.replace_baseline_hunt_exclusions(
        "hunt-a", site="site-a", start=START, end=START + 2 * H, exclusions={},
        spec_versions={SPEC.id: (SPEC.version, SPEC.key_version)},
    )

    changes = apply_exclusion_changes(repo, site="site-a", start=START, end=START + 2 * H, built_by="hunt-a",
                                      now=START + 3 * H)

    assert changes["derived"] == 0 and changes["stale"] == changes["rebuilt_from_source"] >= 1
    assert all("no longer holds every key" in item for item in changes["fallbacks"])
    assert repo.baseline_segments(statuses=["active"]) == []
    # a lookback rebuilds the retired hours from source under the current union
    repo.create_hunt("build", {}, "manifest-build", "test")
    result = LookbackWriter(
        repo, FakeHistory([SWEEP_IMPLANT, LATER_IMPLANT, *ROUTINE]), site="site-a", specs=[SPEC],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        now=lambda: START + 3 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + 2 * H)
    assert result.complete == 2 and result.gaps == ()


def test_a_lookback_segment_over_the_cited_hours_is_derived_too_and_stays_unhunted_history():
    repo = _repo()
    _window(repo)
    repo.create_hunt("build", {}, "manifest-build", "test")
    LookbackWriter(
        repo, FakeHistory([SWEEP_IMPLANT, LATER_IMPLANT, *ROUTINE]), site="site-a", specs=[SPEC],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        now=lambda: START + 3 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + 2 * H)
    assert {row["origin"] for row in repo.baseline_segments(statuses=["active"])} == {"lookback"}
    _agent_finding(repo, [LATER_IMPLANT])

    summary = refresh_cited_exclusions(repo, "hunt-a", now=START + 4 * H)

    active = repo.baseline_segments(statuses=["active"])
    assert summary["derived"] == 2 and len(active) == 2
    assert {(row["origin"], row["source_hunt_id"], row["hunted"]) for row in active} == {("lookback", None, 0)}
    counted = {item["key"]["executable"] for row in active for item in repo.baseline_counts(row["id"])}
    assert not counted & {"/tmp/.x/implant-a", "/tmp/.x/implant-b"} and "/usr/bin/id" in counted


def test_twenty_thousand_keys_with_hundreds_cited_by_the_agent_equal_the_run_that_cited_them_from_the_start():
    volume = [_event(f"bulk-{index}", f"/opt/fleet/bin/tool-{index:05d}", 10 + index % 100)
              for index in range(20_000)]
    cited = volume[:400]

    reference_repo = _repo()
    _window(reference_repo, extra=volume)
    _agent_finding(reference_repo, [LATER_IMPLANT, *cited])      # known before the finish
    _finish_run(reference_repo)
    reference = _history(reference_repo)

    repo = _finished_with_agent_pending(extra=volume)
    _agent_finding(repo, [LATER_IMPLANT, *cited])
    summary = refresh_cited_exclusions(repo, "hunt-a", now=START + timedelta(days=1))

    assert summary["derived"] == len(reference) and summary["rebuilt_from_source"] == 0
    assert _history(repo) == reference
    counted = {name for row in reference for name, _count in row[-1]}
    assert len(counted) == 20_000 + len(ROUTINE) - len(cited)
