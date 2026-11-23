"""Hours a hunt has not finished hunting never read as normal history.

From the moment a hunt runs until a finish whose record-citing stages all ran to their end, each (target, spec) of
its window is marked: its findings' cited keys are not all known. A later hunt's lookback still rebuilds those hours
as cover, but its frozen snapshot flags the segments over them, and a key seen in history only there is judged
unresolved with the unfinished hunt named, never common. Never quieter: a key absent from history stays first seen,
and one also seen in complete hours stays common. The marks go at the resumed finish or with the hunt.
"""
from __future__ import annotations

from datetime import timedelta

from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.playbook import ExecPathBaseline
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import KeyContext
from romulus.config import Settings
from romulus.hunt import controls
from romulus.hunt import run as hunt_run
from romulus.hunt.baseline_stage import SnapshotView
from romulus.hunt.baseline_writer import UNFINISHED_REASON, mark_history_incomplete
from romulus.sources.models import Window
from romulus.store.repo import Repo
from tests.test_baseline_held_history import (
    LATER_IMPLANT,
    SWEEP_IMPLANT,
    _finish_run,
    _later_stage_finding,
    _stop_after_sweep,
    _window,
)
from tests.test_baseline_hunt_writer import _event, _manifest, _repo
from tests.test_baseline_lookback import FakeHistory
from tests.test_baseline_writer_hours import SPEC, START, H

EARLIER = _event("earlier-w", "/usr/bin/w", -50)          # the hour before the stopped hunt's window: complete
MARKED_ONLY = _event("routine-id", "/usr/bin/id", 6)       # seen in history only inside the stopped hunt's hours
ALSO_EARLIER = _event("routine-w", "/usr/bin/w", 75)       # inside them too, and in the complete hour before
LATER = Window(start=START + 2 * H, end=START + 3 * H)


def _later_verdicts(repo: Repo, *, hunt_id: str = "later") -> dict[str, tuple[str, str]]:
    """A later hunt (the next window) fills its lookback from source over the three hours before it, freezes its
    history and judges four keys it saw: {executable: (verdict, reason)}."""
    later = _manifest()
    later["window"] = {"start": LATER.start.isoformat(), "end": LATER.end.isoformat()}
    repo.create_hunt(hunt_id, later, f"manifest-{hunt_id}", "test")
    LookbackWriter(
        repo, FakeHistory([EARLIER, SWEEP_IMPLANT, LATER_IMPLANT, MARKED_ONLY, ALSO_EARLIER]), site="site-a",
        specs=[SPEC], normalizer="fixture@1", budget=LookbackBudget(queries=20, records=20, seconds=20),
        now=lambda: LATER.start,
    ).fill(hunt_id=hunt_id, targets=["host-index"], start=START - H, end=LATER.start)
    repo.set_rule_cell(hunt_id, SPEC.id, SPEC.version, "host-index", LATER.key(), "evaluated_complete", 0, 4, {})
    snapshot = SnapshotPlanner(repo).freeze(
        hunt_id=hunt_id, window_start=LATER.start, lookback=3 * H, min_live_hours=1, site="site-a",
        targets=["host-index"], specs=[SPEC],
    )
    seen = [_event(f"{hunt_id}-{name}", path, 125 + index) for index, (name, path) in enumerate(
        [("implant", "/tmp/.x/implant-b"), ("id", "/usr/bin/id"), ("w", "/usr/bin/w"), ("new", "/tmp/new-tool")])]
    for event in seen:
        repo.save_evidence(hunt_id, [event], {event.raw[0].key: {"event": event.id}}, None)
        repo.upsert_baseline_observations({
            "hunt_id": hunt_id, "spec_id": SPEC.id, "spec_version": SPEC.version, "scope_kind": key.scope_kind,
            "scope": key.scope, "key_id": key.key_id, "key_digest": key.key_digest, "key": key.key,
            "window_count": 1, "first_ts": event.ts, "last_ts": event.ts, "first_event_id": event.id,
            "verdict": "unresolved", "reason": "baseline judgement pending",
        } for key in SPEC.keys(event, KeyContext()))
    list(SnapshotView(repo, hunt_id, LATER, snapshot, min_live_hours=1, networks_configured=True)
         .judge(ExecPathBaseline()))
    return {row["key"]["executable"]: (row["verdict"], row["reason"])
            for row in repo.baseline_observations(hunt_id)}


def test_a_stopped_hunt_never_resumed_leaves_its_hours_unresolved_for_a_later_hunt_never_common():
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    assert {(row["target"], row["spec_id"]) for row in repo.baseline_exclusions_incomplete(hunt_id="hunt-a")} == {
        ("host-index", SPEC.id)}

    verdicts = _later_verdicts(repo)

    # what the stopped hunt's unrun stages would have cited (implant B) is in the rebuilt history, yet never common
    assert verdicts["/tmp/.x/implant-b"][0] == "unresolved"
    assert "hunt-a" in verdicts["/tmp/.x/implant-b"][1] and "incomplete" in verdicts["/tmp/.x/implant-b"][1]
    assert verdicts["/usr/bin/id"][0] == "unresolved"
    # never quieter: a key also seen in the complete hour stays common, and an absent key stays first seen
    assert verdicts["/usr/bin/w"][0] == "common"
    assert verdicts["/tmp/new-tool"][0] == "first_seen"
    # the snapshot flags only the segments over the stopped hunt's hours
    snapshot = repo.baseline_snapshot("later")
    flagged = snapshot["coverage"][f"host-index|{SPEC.id}"]["incomplete"]
    assert flagged["hunts"] == ["hunt-a"] and flagged["hunt_count"] == 1 and len(flagged["segment_ids"]) == 2


def test_without_the_marks_the_same_history_read_the_attack_activity_as_common():
    """The control: the verdict the marks prevent. Same store and history, with the stopped hunt's marks gone."""
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    repo.clear_baseline_exclusions_incomplete("hunt-a")

    verdicts = _later_verdicts(repo)

    assert verdicts["/tmp/.x/implant-b"][0] == "common"
    assert "incomplete" not in repo.baseline_snapshot("later")["coverage"][f"host-index|{SPEC.id}"]


def test_the_resumed_finish_clears_the_marks_and_its_own_history_leaves_the_cited_keys_out():
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    repo.claim_hunt("hunt-a", 600, resume=True)
    _later_stage_finding(repo)
    _finish_run(repo)

    assert repo.baseline_exclusions_incomplete(hunt_id="hunt-a") == []
    verdicts = _later_verdicts(repo)
    # the finished hunt's own segments cover its hours, with both implants excluded
    assert verdicts["/tmp/.x/implant-b"][0] == "first_seen"
    assert verdicts["/usr/bin/id"][0] == "common" and verdicts["/usr/bin/w"][0] == "common"
    assert "incomplete" not in repo.baseline_snapshot("later")["coverage"][f"host-index|{SPEC.id}"]


def test_deleting_the_unfinished_hunt_removes_its_marks():
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    assert repo.baseline_exclusions_incomplete(hunt_id="hunt-a")

    counts = repo.delete_hunt("hunt-a", "test", now=START + timedelta(days=1))

    assert counts["baseline_exclusions_incomplete"] == 1
    assert repo.baseline_exclusions_incomplete() == []


def test_a_finish_whose_cited_keys_cannot_all_be_known_keeps_those_pairs_marked():
    repo = _repo()
    _window(repo)
    # a finding citing a record that is not retained: its keys are unknown, so the pair is blocked
    repo.save_candidate({
        "id": "unretained", "hunt_id": "hunt-a", "rule_id": "host.fixture", "rule_version": "1", "claim": "x",
        "claim_type": "observed_action", "event_ids": ["never-stored"], "context_event_ids": [],
        "predicate_fields": [], "entities": [], "ts": START, "severity": "high", "confidence": "high",
        "lane": "high", "priority": 1.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
        "next_checks": [], "group_key": "unretained", "source_case_id": None, "source_anchor_id": None,
        "source_link_id": None,
    })
    _finish_run(repo)

    (mark,) = repo.baseline_exclusions_incomplete(hunt_id="hunt-a")
    assert "not retained" in mark["reason"]


def test_marks_are_one_row_per_target_and_spec_however_often_a_hunt_runs():
    repo = _repo()
    manifest = _manifest()
    manifest["targets"] = [f"host-{index:03d}" for index in range(200)]
    repo.create_hunt("hunt-big", manifest, "manifest-big", "test")
    for _ in range(3):
        assert mark_history_incomplete(repo, "hunt-big") == 200
    rows = repo.baseline_exclusions_incomplete(hunt_id="hunt-big")
    assert len(rows) == 200 and {row["reason"] for row in rows} == {UNFINISHED_REASON}


def test_a_hunt_stopped_during_its_sweep_leaves_its_hours_marked(monkeypatch, tmp_path):
    """The run marks its hours when it starts; a stop in the sweep never reaches a finish that clears them."""
    from tests.test_hunt_controls import _patched_run, _StoppingSweep
    repo = _repo()
    manifest = {**_manifest(), "ai_agent": {"requested": False}}
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    owner = repo.claim_hunt("hunt-a", 600)["lease_owner"]
    _patched_run(monkeypatch, repo)
    monkeypatch.setattr(hunt_run, "Sweep", _StoppingSweep)
    monkeypatch.setattr(controls, "STOP_CHECK_SECONDS", 0.0)

    result = hunt_run.run_hunt(Settings(home=tmp_path), "hunt-a", claimed_owner=owner)

    assert result["execution_state"] == "partial" and result["stopped"]["stage"] == "sweep"
    (mark,) = repo.baseline_exclusions_incomplete(hunt_id="hunt-a")
    assert mark["reason"] == UNFINISHED_REASON and mark["start"] == START
