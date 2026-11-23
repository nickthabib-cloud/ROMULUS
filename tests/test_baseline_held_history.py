"""A run that ended before every record-citing stage ran to its end publishes no hunt-derived history.

Its findings are incomplete, so the keys of finding-associated activity that history must leave out are not all known:
segments written then would carry attack activity as normal history for later hunts. The run still records its
exclusion ledger and keeps its window material; the resumed run's finish writes exactly what an uninterrupted run
writes.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import KeyContext
from romulus.config import Settings
from romulus.hunt import controls
from romulus.hunt import run as hunt_run
from romulus.hunt.run import _finish
from romulus.store.repo import Repo
from tests.test_baseline_hunt_writer import _candidate, _event, _manifest, _repo
from tests.test_baseline_lookback import FakeHistory
from tests.test_baseline_writer_hours import SPEC, START, H, _hunt, _sweep_cell

STOP_AT_BASELINE = {"detail": "web:alice", "stage": "baseline stage",
                    "not_run": ["baseline stage", "network-host join", "expansion", "AI agent"]}
NOT_RUN = {"status": "not_run", "stop_reason": "not run: stopped by analyst"}
EXPANDED = {"status": "completed", "stop_reason": "fixpoint"}
PACKETS = {"finished": True, "status": "complete"}
BASELINE = {"finished": True, "status": "complete", "stage_failed": False}


def _finish_run(repo: Repo, *, stopped=None, packet=PACKETS, baseline=BASELINE, expansion=EXPANDED,
                budget: int | None = None) -> dict:
    return _finish(
        repo, "hunt-a", {"status": "disabled", "mode": "off"},
        {"finished": True, "complete": True, "partial_reasons": [], "stats": {}},
        packet_summary=packet, baseline_summary=baseline, expansion_summary=expansion, stopped=stopped,
        **({} if budget is None else {"retain_budget_bytes": budget}),
    )


def _stop_after_sweep(repo: Repo) -> dict:
    return _finish_run(repo, stopped=STOP_AT_BASELINE, packet=PACKETS, baseline={}, expansion=NOT_RUN)


def _writer(repo: Repo) -> dict:
    return repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]


SWEEP_IMPLANT = _event("implant-a", "/tmp/.x/implant-a", 5)          # a sweep finding cites it
LATER_IMPLANT = _event("implant-b", "/tmp/.x/implant-b", 70)         # only a later stage's finding cites it
ROUTINE = [_event("routine-1", "/usr/bin/id", 6), _event("routine-2", "/usr/bin/w", 75)]


def _window(repo: Repo, extra=()) -> None:
    """A two-hour hunt whose sweep staged both implants and routine activity, and whose sweep cited implant A."""
    _hunt(repo, hours=2)
    events = [SWEEP_IMPLANT, LATER_IMPLANT, *ROUTINE, *extra]
    _sweep_cell(repo, [item for item in events if item.ts < START + H], START, START + H)
    _sweep_cell(repo, [item for item in events if item.ts >= START + H], START + H, START + 2 * H)
    _candidate(repo, SWEEP_IMPLANT, candidate_id="sweep-finding")


def _later_stage_finding(repo: Repo) -> None:
    """What the baseline stage or expansion publishes once it runs: a finding citing implant B."""
    _candidate(repo, LATER_IMPLANT, candidate_id="later-finding")


def _digests(event) -> list[str]:
    return sorted(key.key_digest for key in SPEC.keys(event, KeyContext()))


def _history(repo: Repo) -> list[tuple]:
    """The active hunt-derived history: identity, exclusions, rows digest and counted keys of every segment."""
    return sorted(
        (row["id"], row["start"], row["end"], tuple(row["excluded_keys"]), row["exclusion_digest"],
         row["rows_digest"], row["events_total"],
         tuple(sorted((item["key"]["executable"], item["count"]) for item in repo.baseline_counts(row["id"]))))
        for row in repo.baseline_segments(statuses=["active"])
    )


def _reference(extra=()) -> list[tuple]:
    """An uninterrupted run over the same window: the sweep and the later stage both publish, then it finishes."""
    repo = _repo()
    _window(repo, extra)
    _later_stage_finding(repo)
    assert _finish_run(repo)["execution_state"] == "completed_within_scope"
    return _history(repo)


def _later_snapshot(repo: Repo) -> dict:
    """A later hunt (the next window) freezes its history over the stopped hunt's two hours."""
    later = _manifest()
    later["window"] = {"start": (START + 2 * H).isoformat(), "end": (START + 3 * H).isoformat()}
    repo.create_hunt("later", later, "manifest-later", "test")
    snapshot = SnapshotPlanner(repo).freeze(
        hunt_id="later", window_start=START + 2 * H, lookback=2 * H, min_live_hours=1, site="site-a",
        targets=["host-index"], specs=[SPEC],
    )
    return snapshot["coverage"][f"host-index|{SPEC.id}"]


# ---- the stop after the sweep ----------------------------------------------------------------------------------

def test_a_hunt_stopped_after_its_sweep_publishes_no_history_and_says_why():
    repo = _repo()
    _window(repo)

    result = _stop_after_sweep(repo)

    assert result["execution_state"] == "partial"
    assert repo.baseline_segments() == []
    writer = _writer(repo)
    assert writer["status"] == "held" and writer["written"] == 0
    # the AI agent runs after the deterministic finish in every run, so it never holds the writer
    assert writer["held"]["stages"] == ["baseline stage", "network-host join", "expansion"]
    assert "not all known" in writer["specs"][SPEC.id]["reason"]
    # what the sweep did find is in the exclusion ledger at once: a lookback over these hours leaves it out
    assert repo.baseline_exclusion_keys(
        site="site-a", target="host-index", spec_id=SPEC.id, spec_version=SPEC.version,
        key_version=SPEC.key_version, start=START, end=START + 2 * H,
    ) == _digests(SWEEP_IMPLANT)
    # the material stays for the resumed finish, charged to the disk budget
    assert writer["material"]["kept"] is True and "held back" in writer["material"]["reason"]
    assert repo.baseline_window_retention("hunt-a")["bytes"] == writer["material"]["bytes"] > 0


def test_the_resumed_finish_writes_exactly_what_an_uninterrupted_run_writes():
    reference = _reference()
    assert reference, "the reference run writes history"
    assert all("/tmp/.x/implant-a" not in str(row) and "/tmp/.x/implant-b" not in str(row) for row in reference)

    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    assert _history(repo) == []

    repo.claim_hunt("hunt-a", 600, resume=True)
    _later_stage_finding(repo)
    result = _finish_run(repo)

    assert result["execution_state"] == "completed_within_scope"
    assert _history(repo) == reference
    assert [row for row in repo.baseline_segments() if row["status"] != "active"] == []
    writer = _writer(repo)
    assert writer["status"] == "complete" and writer["written"] == len(reference)
    assert writer["material"]["kept"] is False and repo.baseline_window_retention("hunt-a") is None


def test_a_hunt_stopped_and_never_resumed_gives_a_later_hunt_no_history_from_it():
    stopped = _repo()
    _window(stopped)
    _stop_after_sweep(stopped)

    coverage = _later_snapshot(stopped)

    assert coverage["segment_ids"] == [] and coverage["effective_hours"] == 0
    assert coverage["status"] != "resolved"
    # not vacuous: the same later hunt reads the complete run's history over the same hours
    complete = _repo()
    _window(complete)
    _later_stage_finding(complete)
    _finish_run(complete)
    assert _later_snapshot(complete)["segment_ids"]


def test_a_lookback_over_a_stopped_hunts_hours_is_unhunted_history_without_what_it_found():
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    repo.create_hunt("build", {}, "manifest-build", "test")

    result = LookbackWriter(
        repo, FakeHistory([SWEEP_IMPLANT, LATER_IMPLANT, *ROUTINE]), site="site-a", specs=[SPEC],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        now=lambda: START + 3 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + 2 * H)

    assert result.complete == 2
    segments = repo.baseline_segments(statuses=["active"])
    # read from the source as history nobody hunted, never as the stopped hunt's own
    assert {(row["origin"], row["source_hunt_id"], row["hunted"]) for row in segments} == {("lookback", None, 0)}
    counted = {item["key"]["executable"] for row in segments for item in repo.baseline_counts(row["id"])}
    assert "/tmp/.x/implant-a" not in counted
    # What the stopped hunt's unrun stages would have cited is not in its ledger, so the lookback counts it; the
    # hunt's incomplete-exclusion marks make a later judgement of it unresolved, never common
    # (tests/test_baseline_incomplete_history.py).
    assert "/tmp/.x/implant-b" in counted
    assert repo.baseline_exclusions_incomplete(hunt_id="hunt-a")


# ---- through the real stop and the stages after the sweep ---------------------------------------------------

def test_a_stop_honoured_before_the_baseline_stage_holds_the_writer_and_the_resumed_stages_write(tmp_path,
                                                                                                monkeypatch):
    """The stop's not-run list comes from the run's own stop check, and the resumed stages publish the later
    finding: the wiring from `_stages_after_sweep` into `_finish`, not hand-built summaries."""
    reference = _reference()
    settings = Settings(home=tmp_path)
    repo = _repo()
    _window(repo)
    owner = repo.get_hunt("hunt-a")["lease_owner"]
    sweep = {"finished": True, "complete": True, "partial_reasons": [], "stats": {}}
    repo.audit("system", "hunt.sweep_summary", "hunt-a", sweep, owner_token=owner)
    monkeypatch.setattr(hunt_run, "run_rank_pass", lambda *_a, **_k: None)
    monkeypatch.setattr(hunt_run, "_packet_stage", lambda *_a, **_k: dict(PACKETS))
    repo.audit("system", "hunt.packet_summary", "hunt-a", dict(PACKETS), owner_token=owner)

    def never(*_args, **_kwargs):
        pytest.fail("a stage the stop skipped ran")

    for name in ("_baseline_stage", "_join_pass", "_run_expansion_safely"):
        monkeypatch.setattr(hunt_run, name, never)
    repo.request_hunt_stop("hunt-a", "hunt", "web:alice")
    watch = controls.StopWatch(repo, "hunt-a", ("hunt",), ttl=0)
    packet, baseline, expansion, stop = hunt_run._stages_after_sweep(
        settings, repo, object(), "hunt-a", None, {}, owner, watch, packet_summary=dict(PACKETS))
    assert stop["stage"] == "baseline stage"
    result = _finish(repo, "hunt-a", {"status": "disabled", "mode": "off"}, sweep, packet_summary=packet,
                     baseline_summary=baseline, expansion_summary=expansion, owner_token=owner, stopped=stop)

    assert result["execution_state"] == "partial"
    assert _writer(repo)["status"] == "held" and repo.baseline_segments() == []

    # the resume: the stop is cleared and the stages that did not run now run and publish
    before = repo.latest_stop("hunt-a")["id"]
    owner = repo.claim_hunt("hunt-a", 600, resume=True)["lease_owner"]
    repo.clear_stops("hunt-a", "cli:web:alice", up_to_id=before)

    def baseline_stage(*_args, **_kwargs):
        _later_stage_finding(repo)
        return dict(BASELINE)

    monkeypatch.setattr(hunt_run, "_baseline_stage", baseline_stage)
    monkeypatch.setattr(hunt_run, "_join_pass", lambda *_a, **_k: repo.audit(
        "system", "hunt.join_summary", "hunt-a", {"finished": True, "complete": True}))
    monkeypatch.setattr(hunt_run, "_run_expansion_safely", lambda *_a, **_k: dict(EXPANDED))
    recorded = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]
    packet, baseline, expansion, stop = hunt_run._stages_after_sweep(
        settings, repo, object(), "hunt-a", None, {}, owner, controls.StopWatch(repo, "hunt-a", ("hunt",), ttl=0),
        packet_summary=dict(PACKETS), baseline_summary=recorded)
    assert stop is None
    _finish(repo, "hunt-a", {"status": "disabled", "mode": "off"}, sweep, packet_summary=packet,
            baseline_summary=baseline, expansion_summary=expansion, owner_token=owner)

    assert _writer(repo)["status"] == "complete"
    assert _history(repo) == reference


# ---- a crash between writing and publishing ------------------------------------------------------------------

class _Killed(BaseException):
    """The worker process dying mid-write: nothing in the finish catches it."""


def test_a_finish_killed_between_writing_and_publishing_leaves_no_cover_and_the_rerun_writes_it(monkeypatch):
    reference = _reference()
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    repo.claim_hunt("hunt-a", 600, resume=True)
    _later_stage_finding(repo)

    def killed(*_args, **_kwargs):
        raise _Killed()

    monkeypatch.setattr(Repo, "finalize_baseline_segment", killed)
    with pytest.raises(_Killed):
        _finish_run(repo)
    monkeypatch.undo()

    # the rows were written but never published: a building segment is never cover
    assert {row["status"] for row in repo.baseline_segments()} == {"building"}
    assert _history(repo) == []
    assert _later_snapshot(repo)["segment_ids"] == []
    assert repo.get_hunt("hunt-a")["execution_state"] == "running"

    # the resume of the killed run reaches the finish again and reclaims its own build
    _finish_run(repo)
    assert _history(repo) == reference
    assert {row["status"] for row in repo.baseline_segments()} == {"active"}


def test_a_killed_finish_never_resumed_is_reaped_and_never_becomes_cover(monkeypatch):
    repo = _repo()
    _window(repo)
    _later_stage_finding(repo)
    monkeypatch.setattr(Repo, "finalize_baseline_segment", lambda *_a, **_k: (_ for _ in ()).throw(_Killed()))
    with pytest.raises(_Killed):
        _finish_run(repo)
    monkeypatch.undo()

    building = repo.baseline_segments(statuses=["building"])
    assert building and repo.baseline_segments(statuses=["active"]) == []
    assert _later_snapshot(repo)["segment_ids"] == []
    # an abandoned build is reaped by the next writer or lookback that cleans up; it never turns into cover
    assert repo.cleanup_baseline_building(before=START + timedelta(days=3650)) == len(building)
    assert repo.baseline_segments() == []


# ---- a resumed run stopped again ---------------------------------------------------------------------------

def test_a_resume_stopped_again_mid_expansion_keeps_the_material_and_the_next_resume_writes():
    reference = _reference()
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)

    # first resume: the baseline stage finishes, expansion is stopped part way
    repo.claim_hunt("hunt-a", 600, resume=True)
    stopped = {"detail": "web:alice", "stage": "expansion", "not_run": []}
    _finish_run(repo, stopped=stopped, expansion={"status": "partial", "stopped": "web:alice",
                                                  "stop_reason": "stopped by analyst"})
    writer = _writer(repo)
    assert writer["status"] == "held" and writer["held"]["stages"] == ["expansion"]
    assert repo.baseline_segments() == []
    # an earlier finish kept the material, yet this one must not release it: nothing has written the window yet
    assert writer["material"]["kept"] is True
    assert repo.baseline_window_material_pairs("hunt-a") == [(SPEC.id, "host-index")]

    # second resume: expansion finishes and publishes
    repo.claim_hunt("hunt-a", 600, resume=True)
    _later_stage_finding(repo)
    _finish_run(repo)
    assert _history(repo) == reference
    assert repo.baseline_window_retention("hunt-a") is None


# ---- which ends hold the writer ------------------------------------------------------------------------------

@pytest.mark.parametrize("ending, stages", [
    ({"expansion": {"status": "failed", "stop_reason": "expansion error: boom"}}, ["expansion"]),
    ({"packet": {"status": "failed", "finished": False, "error": "boom"}}, ["packet stage"]),
    ({"baseline": {"status": "failed", "finished": False, "stage_failed": True}}, ["baseline stage"]),
    ({"join": {"finished": False, "complete": False, "error": "boom"}}, ["network-host join"]),
])
def test_a_record_citing_stage_that_did_not_finish_holds_the_writer(ending, stages):
    ending = dict(ending)
    repo = _repo()
    _window(repo)
    if "join" in ending:
        repo.audit("system", "hunt.join_summary", "hunt-a", ending.pop("join"))

    result = _finish_run(repo, **ending)

    # partial, so a resume runs the stage again and its finish writes the history held back here
    assert result["execution_state"] == "partial"
    writer = _writer(repo)
    assert writer["status"] == "held" and writer["held"]["stages"] == stages
    assert repo.baseline_segments() == []
    assert writer["material"]["kept"] is True


@pytest.mark.parametrize("ending", [
    {"expansion": {"status": "partial", "stop_reason": "source query budget exhausted"}},
    {"expansion": {"status": "disabled", "stop_reason": "disabled by --no-expand"}},
    {"packet": {"status": "partial", "finished": True, "partial_reasons": ["a capture was unreadable"]}},
    {"baseline": {"finished": True, "status": "partial", "stage_failed": True}},
    {"join": {"finished": True, "complete": False}},
    {"stopped": {"detail": "web:alice", "stage": "AI agent", "not_run": ["AI agent"]}},
])
def test_a_run_whose_record_citing_stages_all_ran_to_their_end_writes(ending):
    """Partial coverage is not an unfinished stage: an expansion cut by its budget, a packet stage that could not
    read everything, or a baseline stage with history gaps each ran to its end, and a resume would not run it."""
    ending = dict(ending)
    repo = _repo()
    _window(repo)
    _later_stage_finding(repo)
    if "join" in ending:
        repo.audit("system", "hunt.join_summary", "hunt-a", ending.pop("join"))

    _finish_run(repo, **ending)

    writer = _writer(repo)
    assert writer["status"] == "complete" and writer["written"] == 1
    assert _history(repo) == _reference()


def test_the_unfinished_stages_come_from_the_stop_and_the_recorded_summaries():
    repo = _repo()
    _hunt(repo, hours=1)
    assert hunt_run.unfinished_citing_stages(repo, "hunt-a", packet_summary=None, expansion_summary=None,
                                             stopped=STOP_AT_BASELINE) == [
        "baseline stage", "network-host join", "expansion"]
    repo.audit("system", "hunt.join_summary", "hunt-a", {"finished": False})
    assert hunt_run.unfinished_citing_stages(
        repo, "hunt-a", packet_summary={"finished": False}, stopped=None,
        expansion_summary={"status": "partial", "stopped": "web:alice"},
    ) == ["packet stage", "network-host join", "expansion"]
    repo.audit("system", "hunt.join_summary", "hunt-a", {"finished": True})
    assert hunt_run.unfinished_citing_stages(repo, "hunt-a", packet_summary=PACKETS, expansion_summary=EXPANDED,
                                             stopped=None) == []


# ---- volume --------------------------------------------------------------------------------------------------

def test_a_large_window_held_at_a_stop_and_written_at_the_resume_equals_the_uninterrupted_run():
    """Twenty thousand distinct keys, a few hundred cited by the sweep and a few hundred more by the later stage."""
    volume = [_event(f"bulk-{index}", f"/opt/fleet/bin/tool-{index:05d}", 10 + index % 100)
              for index in range(20_000)]
    sweep_cited, later_cited = volume[:300], volume[300:600]

    def run(*, stop: bool) -> list[tuple]:
        repo = _repo()
        _window(repo, extra=volume)
        for index, event in enumerate(sweep_cited):
            _candidate(repo, event, candidate_id=f"sweep-bulk-{index}")
        if stop:
            _stop_after_sweep(repo)
            assert repo.baseline_segments() == [] and _writer(repo)["material"]["bytes"] > 0
            repo.claim_hunt("hunt-a", 600, resume=True)
        _later_stage_finding(repo)
        for index, event in enumerate(later_cited):
            _candidate(repo, event, candidate_id=f"later-bulk-{index}")
        _finish_run(repo)
        return _history(repo)

    reference = run(stop=False)
    resumed = run(stop=True)
    assert resumed == reference
    counted = {name for row in reference for name, _count in row[-1]}
    assert len(counted) == 20_000 + len(ROUTINE) - 600
    assert not counted & {event.fields["process.executable"].value for event in [*sweep_cited, *later_cited]}
