"""History never publishes a build made from an older reading of the cited-key union.

Every publisher (the hunt writer, the lookback writer and a derivation) checks, inside the transaction that would make
its build cover, that the durable union over the build's hours holds no key the build lacks; a derivation also
retires the segment it replaces first and is activated only when that retirement happened. A build that lost a race
is discarded and built again from the union as it then stands, or its hours stay out of history with the reason
named. Another hunt's citation can therefore never come back into active cover through a slower publisher.
"""
from __future__ import annotations

import time
from datetime import timedelta

from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.hunt.baseline_writer import _derive_segment, apply_exclusion_changes, refresh_cited_exclusions
from romulus.store import repo as repo_module
from romulus.store.repo import Repo
from tests.test_baseline_agent_exclusions import _agent_finding, _finished_with_agent_pending
from tests.test_baseline_held_history import (
    LATER_IMPLANT,
    ROUTINE,
    SWEEP_IMPLANT,
    _digests,
    _finish_run,
    _later_snapshot,
    _window,
)
from tests.test_baseline_hunt_writer import _repo
from tests.test_baseline_lookback import FakeHistory
from tests.test_baseline_writer_hours import SPEC, START, H

SPANS = {SPEC.id: (SPEC.version, SPEC.key_version)}
WINDOW = (START, START + 2 * H)


def _cite(repo: Repo, hunt_id: str, event) -> None:
    """Another hunt over the same hours cites `event`: its key joins the durable union."""
    if repo.get_hunt(hunt_id) is None:
        repo.create_hunt(hunt_id, repo.get_hunt("hunt-a")["manifest"], f"manifest-{hunt_id}", "test")
    repo.add_baseline_hunt_exclusions(hunt_id, site="site-a", start=WINDOW[0], end=WINDOW[1],
                                      exclusions={("host-index", SPEC.id): set(_digests(event))}, spec_versions=SPANS)


def _one_generation_excluding(repo: Repo, *events) -> list[dict]:
    """Active cover over the window: never two segments over one hour, each excluding every given key."""
    active = sorted(repo.baseline_segments(statuses=["active"]), key=lambda row: row["start"])
    for first, second in zip(active, active[1:], strict=False):
        assert first["end"] <= second["start"], (first["id"], second["id"])
    wanted = {digest for event in events for digest in _digests(event)}
    for row in active:
        assert wanted <= set(row["excluded_keys"]), row["id"]
    assert repo.baseline_segments(statuses=["building"]) == []
    return active


def _counted(repo: Repo, segment_ids) -> set[str]:
    return {item["key"]["executable"] for segment_id in segment_ids for item in repo.baseline_counts(segment_id)}


# ---- a derivation against another hunt's ------------------------------------------------------------------------

def test_a_derivation_overtaken_between_build_and_publication_never_becomes_cover(monkeypatch):
    """Hunt A's agent refresh builds its replacement; before A publishes, hunt B cites routine-1 and derives the
    complete replacement. A's build is refused inside its publishing transaction, discarded, and A's next pass finds
    nothing left to change. The later hunt's snapshot reads B's complete segment."""
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    real = Repo.publish_derived_baseline_segment
    interleaved = []

    def b_overtakes(self, segment_id, **kwargs):
        if not interleaved:
            interleaved.append(segment_id)
            monkeypatch.setattr(Repo, "publish_derived_baseline_segment", real)
            _cite(self, "hunt-b", ROUTINE[0])
            changes = apply_exclusion_changes(self, site="site-a", start=WINDOW[0], end=WINDOW[1], built_by="hunt-b")
            assert changes["derived"] >= 1
            monkeypatch.setattr(Repo, "publish_derived_baseline_segment", b_overtakes)
        return real(self, segment_id, **kwargs)

    monkeypatch.setattr(Repo, "publish_derived_baseline_segment", b_overtakes)
    summary = refresh_cited_exclusions(repo, "hunt-a")
    monkeypatch.undo()

    assert interleaved and summary["rebuilt_from_source"] == 0
    active = _one_generation_excluding(repo, LATER_IMPLANT, ROUTINE[0], SWEEP_IMPLANT)
    coverage = _later_snapshot(repo)
    assert set(coverage["segment_ids"]) == {row["id"] for row in active} and coverage["effective_hours"] == 2
    counted = _counted(repo, coverage["segment_ids"])
    assert not counted & {"/usr/bin/id", "/tmp/.x/implant-a", "/tmp/.x/implant-b"} and "/usr/bin/w" in counted


def test_a_derivation_read_before_another_published_is_raced_and_never_published():
    """The reviewer's ordering: A reads its change, B derives the complete replacement first, then A derives from
    its stale reading. A finds its segment no longer active and publishes nothing."""
    repo = _finished_with_agent_pending()
    _cite(repo, "hunt-a", LATER_IMPLANT)
    (change_a,) = [change for change in repo.baseline_exclusion_changes(site="site-a", start=WINDOW[0],
                                                                         end=WINDOW[1])][:1]
    _cite(repo, "hunt-b", ROUTINE[0])
    for change in repo.baseline_exclusion_changes(site="site-a", start=WINDOW[0], end=WINDOW[1]):
        assert _derive_segment(repo, change, built_by="hunt-b") == "published"

    assert _derive_segment(repo, change_a, built_by="hunt-a") == "raced"

    active = _one_generation_excluding(repo, LATER_IMPLANT, ROUTINE[0])
    assert "/usr/bin/id" not in _counted(repo, [row["id"] for row in active])


def test_a_derivation_whose_union_grew_after_its_own_reading_is_refused_and_rebuilt(monkeypatch):
    """The union grows between A's re-read and A's publication, with no other derivation in between: the publishing
    transaction refuses the weaker build, and A's next pass derives from the union as it then stands."""
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    real = Repo.publish_derived_baseline_segment
    outcomes = []

    def grows_first(self, segment_id, **kwargs):
        if not outcomes:
            _cite(self, "hunt-b", ROUTINE[0])
        outcomes.append(real(self, segment_id, **kwargs))
        return outcomes[-1]

    monkeypatch.setattr(Repo, "publish_derived_baseline_segment", grows_first)
    summary = refresh_cited_exclusions(repo, "hunt-a")
    monkeypatch.undo()

    assert outcomes[0] == "union_changed" and "published" in outcomes[1:]
    assert summary["derived"] >= 1 and summary["rebuilt_from_source"] == 0
    _one_generation_excluding(repo, LATER_IMPLANT, ROUTINE[0], SWEEP_IMPLANT)


# ---- the hunt writer and the lookback writer ---------------------------------------------------------------------

def test_the_hunt_writer_rebuilds_a_segment_another_hunt_outgrew_before_it_was_published(monkeypatch):
    repo = _repo()
    _window(repo)
    real = Repo.finalize_baseline_segment
    calls = []

    def cited_meanwhile(self, segment_id):
        calls.append(segment_id)
        if len(calls) == 1:
            _cite(self, "hunt-b", ROUTINE[0])
        return real(self, segment_id)

    monkeypatch.setattr(Repo, "finalize_baseline_segment", cited_meanwhile)
    _finish_run(repo)
    monkeypatch.undo()

    assert len(calls) == 2 and calls[0] != calls[1]
    active = _one_generation_excluding(repo, SWEEP_IMPLANT, ROUTINE[0])
    assert len(active) == 1 and "/usr/bin/id" not in _counted(repo, [active[0]["id"]])
    assert {row["id"] for row in repo.baseline_segments()} == {active[0]["id"]}       # the refused build is gone


def test_the_hunt_writer_leaves_hours_unwritten_and_named_when_the_union_keeps_changing(monkeypatch):
    repo = _repo()
    _window(repo)
    real = Repo.finalize_baseline_segment
    others = iter([ROUTINE[0], ROUTINE[1], LATER_IMPLANT])

    def cited_every_time(self, segment_id):
        _cite(self, f"hunt-{len(self.baseline_segments())}-x", next(others))
        return real(self, segment_id)

    monkeypatch.setattr(Repo, "finalize_baseline_segment", cited_every_time)
    _finish_run(repo)
    monkeypatch.undo()

    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert "changed while it was written twice" in writer["specs"][SPEC.id]["reason"]
    assert repo.baseline_segments() == []


def test_a_lookback_build_another_hunt_outgrew_is_a_named_gap_never_cover(monkeypatch):
    repo = _repo()
    repo.create_hunt("hunt-a", {"window": {"start": START.isoformat(), "end": (START + 2 * H).isoformat()}},
                     "manifest-a", "test")
    repo.create_hunt("build", {}, "manifest-build", "test")
    real = Repo.finalize_baseline_segment
    calls = []

    def cited_meanwhile(self, segment_id):
        calls.append(segment_id)
        if len(calls) == 1:
            _cite(self, "hunt-b", ROUTINE[0])
        return real(self, segment_id)

    monkeypatch.setattr(Repo, "finalize_baseline_segment", cited_meanwhile)
    result = LookbackWriter(
        repo, FakeHistory([SWEEP_IMPLANT, LATER_IMPLANT, *ROUTINE]), site="site-a", specs=[SPEC],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        now=lambda: START + 3 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + 2 * H)
    monkeypatch.undo()

    assert any(gap.state == "failed" and "joined the union" in gap.reason for gap in result.gaps)
    assert repo.baseline_segments(statuses=["building"]) == [] or all(
        row["built_by_hunt_id"] == "build" for row in repo.baseline_segments(statuses=["building"]))
    assert "/usr/bin/id" not in _counted(repo, [row["id"] for row in repo.baseline_segments(statuses=["active"])])


# ---- the guard's cost ----------------------------------------------------------------------------------------------

def test_the_activation_guard_holds_the_write_lock_briefly_over_a_large_union(monkeypatch):
    repo = _repo()
    _window(repo)
    keys = {f"{index:064x}" for index in range(50_000)}
    repo.create_hunt("hunt-big", repo.get_hunt("hunt-a")["manifest"], "manifest-big", "test")
    repo.add_baseline_hunt_exclusions("hunt-big", site="site-a", start=WINDOW[0], end=WINDOW[1],
                                      exclusions={("host-index", SPEC.id): keys}, spec_versions=SPANS)
    holds: list[float] = []
    real = repo_module.write_txn

    class Timed:
        def __init__(self, engine):
            self.inner = real(engine)

        def __enter__(self):
            self.began = time.perf_counter()
            return self.inner.__enter__()

        def __exit__(self, *exc):
            try:
                return self.inner.__exit__(*exc)
            finally:
                holds.append(time.perf_counter() - self.began)

    real_finalize = Repo.finalize_baseline_segment

    def timed_finalize(self, segment_id):
        holds.clear()
        monkeypatch.setattr(repo_module, "write_txn", Timed)
        try:
            return real_finalize(self, segment_id)
        finally:
            monkeypatch.setattr(repo_module, "write_txn", real)
            timed_finalize.holds = list(holds)

    monkeypatch.setattr(Repo, "finalize_baseline_segment", timed_finalize)
    _finish_run(repo)
    monkeypatch.undo()

    (segment,) = repo.baseline_segments(statuses=["active"])
    assert len(segment["excluded_keys"]) >= 50_000
    longest = max(timed_finalize.holds)
    print(f"activation guard over {len(keys)} union keys: longest write-lock hold {longest:.3f}s")
    assert longest < 2.0


def test_derivation_builds_are_stamped_when_they_begin(monkeypatch):
    """One clock reading per build, not per pass: a long pass never leaves a build looking abandoned."""
    repo = _finished_with_agent_pending()
    _agent_finding(repo, [LATER_IMPLANT])
    before = repo_module.utcnow()
    refresh_cited_exclusions(repo, "hunt-a")
    assert all(row["created_at"] >= before - timedelta(seconds=1)
               for row in repo.baseline_segments(statuses=["active"]))
