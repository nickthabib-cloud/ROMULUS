"""Hunt-derived history decided hour by hour, one events_total definition for both writers, and bounded retention
of a finished hunt's window counter material."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.playbook import ExecPathBaseline, ExternalDestinationBaseline
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.baseline_stage import SnapshotView
from romulus.hunt.baseline_writer import run_hunt_segment_writer, writable_runs
from romulus.hunt.run import _finish
from romulus.sources.models import Window
from romulus.store import schema
from tests.test_baseline_hunt_writer import _candidate, _event, _manifest, _repo
from tests.test_baseline_lookback import FakeHistory

START = datetime(2026, 2, 1, tzinfo=UTC)
H = timedelta(hours=1)
SPEC = SPEC_BY_ID["bl.exec_path"]


def _auth(event_id: str, minute: int) -> TypedEvent:
    """A record of another family on the same target: never one of exec_path's records."""
    return TypedEvent(
        id=event_id, family="auth", ts=START + timedelta(minutes=minute), host="web01", outcome=Outcome.success,
        fields={"user.name": fv("alice", "fixture"), "service.name": fv("sshd", "fixture")},
        raw=[RawRef(target="host-index", native_id=event_id, digest=f"raw-{event_id}")], normalizer="fixture@1",
    )


def _sweep_cell(repo, events, start, end, *, state="evaluated_complete", hunt_id="hunt-a", playbook=None,
                target="host-index"):
    """Stage one window cell exactly as the sweep does: the playbook's scope, then its cell counter."""
    playbook = playbook or ExecPathBaseline()
    playbook.begin_cell(f"{start.isoformat()}/{end.isoformat()}", (start, end), KeyContext())
    scoped = playbook.scope_partition(sorted(events, key=lambda item: (item.ts, item.id)))
    before = playbook.evaluated
    playbook.consume_scoped_partition(scoped)
    result = playbook.finish_cell()
    repo.save_baseline_window_cell(hunt_id, {
        "rule_id": playbook.spec.id, "version": playbook.spec.version, "target": target,
        "partition": f"{start.isoformat()}/{end.isoformat()}", "state": state, "matched": 0,
        "evaluated": playbook.evaluated - before, "detail": {"reasons": []},
    }, (), counts=result.counts, scope_hours=result.scope_hours, event_hours=result.event_hours)


def _hunt(repo, *, hours=3, hunt_id="hunt-a", spec=SPEC, networks=None):
    """A claimed (running, leased) hunt over `hours` whole hours."""
    manifest = _manifest()
    manifest["window"] = {"start": START.isoformat(), "end": (START + hours * H).isoformat()}
    manifest["baseline"]["specs"] = [{"id": spec.id, "version": spec.version, "key_version": spec.key_version}]
    if networks:
        manifest["internal_networks"] = networks
    repo.create_hunt(hunt_id, manifest, f"manifest-{hunt_id}", "test")
    repo.claim_hunt(hunt_id, 600)


# ---- D2: one events_total definition ------------------------------------------------------------------------

def _equivalence_events():
    # hour 0: nothing; hour 1: only another family's record; hour 2: the spec's own records
    return [_auth("login", 70), _event("first", "/usr/bin/id", 125), _event("second", "/usr/bin/w", 130)]


def _judge(repo, hunt_id="later"):
    """Freeze a later hunt's snapshot over the three hours and judge one known and one new key."""
    window = Window(start=START + 3 * H, end=START + 4 * H)
    later = _manifest()
    later["window"] = {"start": window.start.isoformat(), "end": window.end.isoformat()}
    repo.create_hunt(hunt_id, later, "manifest-later", "test")
    repo.set_rule_cell(hunt_id, SPEC.id, SPEC.version, "host-index", window.key(), "evaluated_complete", 0, 2, {})
    snapshot = SnapshotPlanner(repo).freeze(
        hunt_id=hunt_id, window_start=window.start, lookback=3 * H, min_live_hours=1, site="site-a",
        targets=["host-index"], specs=[SPEC],
    )
    for event in (_event("known", "/usr/bin/id", 190), _event("new", "/tmp/new", 195)):
        repo.save_evidence(hunt_id, [event], {event.raw[0].key: {"event": event.id}}, None)
        keys = SPEC.keys(event, KeyContext())
        repo.upsert_baseline_observations({
            "hunt_id": hunt_id, "spec_id": SPEC.id, "spec_version": SPEC.version,
            "scope_kind": key.scope_kind, "scope": key.scope, "key_id": key.key_id, "key_digest": key.key_digest,
            "key": key.key, "window_count": 1, "first_ts": event.ts, "last_ts": event.ts,
            "first_event_id": event.id, "verdict": "unresolved", "reason": "baseline judgement pending",
        } for key in keys)
    view = SnapshotView(repo, hunt_id, window, snapshot, min_live_hours=1, networks_configured=True)
    claims = [match.claim.replace(snapshot["digest"], "<snapshot>") for match in view.judge(ExecPathBaseline())]
    verdicts = sorted((row["scope"], row["key"]["executable"], row["verdict"])
                      for row in repo.baseline_observations(hunt_id))
    return snapshot["coverage"]["host-index|bl.exec_path"], verdicts, claims


def test_both_writers_give_one_events_total_and_identical_rows_coverage_and_verdicts():
    events = _equivalence_events()
    hunt_repo = _repo()
    _hunt(hunt_repo)
    for hour in range(3):
        _sweep_cell(hunt_repo, [event for event in events if START + hour * H <= event.ts < START + (hour + 1) * H],
                    START + hour * H, START + (hour + 1) * H)
    assert run_hunt_segment_writer(hunt_repo, "hunt-a", hunt_partial=False)["written"] == 1

    lookback_repo = _repo()
    lookback_repo.create_hunt("build", {}, "manifest-build", "test")
    result = LookbackWriter(
        lookback_repo, FakeHistory(events), site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), now=lambda: START + 3 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + 3 * H)
    assert result.complete == 3 and result.gaps == ()

    hunt_segment = hunt_repo.baseline_segments(statuses=["active"])[0]
    hourly = lookback_repo.baseline_segments(statuses=["active"])
    # the spec's own records only, never the other family's record of hour 1
    assert hunt_segment["events_total"] == sum(row["events_total"] for row in hourly) == 2
    assert [row["events_total"] for row in hourly] == [0, 0, 2]
    assert hunt_segment["first_event_hour"] == START + 2 * H
    assert [row["first_event_hour"] for row in hourly] == [None, None, START + 2 * H]
    assert {row["events_basis"] for row in [hunt_segment, *hourly]} == {2}

    counts = lambda repo, segments: sorted(
        (row["scope"], row["key_digest"], row["bucket"], row["count"], row["first_ts"], row["last_ts"])
        for segment in segments for row in repo.baseline_counts(segment["id"]))
    hours = lambda repo, segments: sorted(
        (row["scope"], row["hour"], row["events"]) for segment in segments for row in repo.baseline_scope_hours(
            segment["id"]))
    assert counts(hunt_repo, [hunt_segment]) == counts(lookback_repo, hourly)
    assert hours(hunt_repo, [hunt_segment]) == hours(lookback_repo, hourly)

    hunt_coverage, hunt_verdicts, hunt_claims = _judge(hunt_repo)
    lookback_coverage, lookback_verdicts, lookback_claims = _judge(lookback_repo)
    for name in ("effective_start", "effective_hours", "absent_before", "status", "gaps"):
        assert hunt_coverage[name] == lookback_coverage[name], name
    # the history starts at the first hour holding one of the spec's records, whichever writer covered it
    assert hunt_coverage["effective_start"] == (START + 2 * H).isoformat()
    assert hunt_coverage["status"] == "shortened"
    assert hunt_verdicts == lookback_verdicts
    assert {verdict for *_rest, verdict in hunt_verdicts} == {"common", "first_seen"}
    # the claims differ only by provenance: lookback history was never itself hunted
    provenance = "The selected history was not itself hunted. "
    assert all(provenance in claim for claim in lookback_claims)
    assert hunt_claims == [claim.replace(provenance, "") for claim in lookback_claims] and len(hunt_claims) == 2


def test_segments_counted_another_way_are_never_selected_and_their_hours_refill():
    repo = _repo()
    repo.create_hunt("build", {}, "manifest-build", "test")
    with repo.engine.begin() as connection:
        connection.execute(schema.baseline_segment.insert().values(
            id="legacy", site="site-a", target="host-index", spec_id=SPEC.id, spec_version=SPEC.version,
            key_version=SPEC.key_version, normalizer="fixture@1", start=START, end=START + H, bucket="day",
            origin="lookback", exclusion_digest="none", excluded_keys=[], hunted=0, events_total=9,
            events_basis=1, first_event_hour=None, rows_digest="legacy", status="active", created_at=START,
        ))
    source = FakeHistory([_event("one", "/usr/bin/id", 5)])

    result = LookbackWriter(
        repo, source, site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), now=lambda: START + H,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=START + H)

    assert result.complete == 1 and len(source.fetches) == 1
    active = repo.baseline_segments(statuses=["active"])
    assert sorted(row["events_basis"] for row in active) == [1, 2]
    assert repo.baseline_segments_for_cover(
        site="site-a", target="host-index", spec_id=SPEC.id, spec_version=SPEC.version,
        key_version=SPEC.key_version, start=START, end=START + H,
    )[0]["events_basis"] == 2


# ---- O1: the write decision is per hour ---------------------------------------------------------------------

def _finish_partial_for_expansion(repo, hunt_id="hunt-a", **kwargs):
    return _finish(
        repo, hunt_id, {"status": "disabled", "stop_reason": ""},
        {"finished": True, "complete": True, "partial_reasons": [], "stats": {}},
        expansion_summary={"status": "partial", "stop_reason": "source query budget exhausted"},
        baseline_summary={"finished": True, "status": "partial", "stage_failed": False}, **kwargs,
    )


def test_a_hunt_partial_for_expansion_writes_its_complete_hours_and_keeps_its_material():
    repo = _repo()
    _hunt(repo, hours=2)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)
    _sweep_cell(repo, [_event("b", "/usr/bin/w", 65)], START + H, START + 2 * H)

    result = _finish_partial_for_expansion(repo)

    assert result["execution_state"] == "partial"
    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert writer["written"] == 1 and writer["specs"][SPEC.id]["reason"] is None
    segment = repo.baseline_segments(statuses=["active"])[0]
    assert (segment["start"], segment["end"], segment["events_total"]) == (START, START + 2 * H, 2)
    # kept for a resume and charged to the disk budget
    assert writer["material"]["kept"] is True and writer["material"]["bytes"] > 0
    assert repo.baseline_window_retention("hunt-a")["bytes"] == writer["material"]["bytes"]
    assert repo.baseline_window_counts("hunt-a", SPEC.id, "host-index")


def test_an_hour_with_an_incomplete_cell_is_not_written_and_stays_absent():
    repo = _repo()
    _hunt(repo, hours=3)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)
    _sweep_cell(repo, [_event("b", "/usr/bin/w", 65)], START + H, START + 2 * H, state="evaluated_partial")
    _sweep_cell(repo, [_event("c", "/usr/bin/df", 125)], START + 2 * H, START + 3 * H)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True)

    spans = sorted((row["start"], row["end"]) for row in repo.baseline_segments(statuses=["active"]))
    assert spans == [(START, START + H), (START + 2 * H, START + 3 * H)]
    assert summary["written"] == 2
    assert summary["specs"][SPEC.id]["reason"] == "host-index: 1 hour(s) not written: an incomplete window cell"
    stored = {row["key"]["executable"] for segment in repo.baseline_segments() for row in repo.baseline_counts(
        segment["id"])}
    assert stored == {"/usr/bin/id", "/usr/bin/df"}


def test_an_hour_no_complete_cell_covers_is_not_written():
    repo = _repo()
    _hunt(repo, hours=2)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)
    # only the first half of the second hour has a cell
    _sweep_cell(repo, [_event("b", "/usr/bin/w", 65)], START + H, START + H + timedelta(minutes=30))

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert [(row["start"], row["end"]) for row in repo.baseline_segments(statuses=["active"])] == [
        (START, START + H)]
    assert "1 hour(s) not written: no complete window cell covers all of it" in summary["specs"][SPEC.id]["reason"]


def test_a_deduplicated_cell_straddling_a_run_start_holds_its_hours_back():
    hours = [START + index * H for index in range(4)]
    cells = [
        {"partition": "p0", "state": "evaluated_partial"},     # [h0, h0:30): the first hour is incomplete
        {"partition": "p1", "state": "evaluated_complete"},    # [h0:30, h2): would start a run at h1
        {"partition": "p2", "state": "evaluated_complete"},    # [h2, h4)
    ]
    spans = {"p0": (hours[0], hours[0] + timedelta(minutes=30)),
             "p1": (hours[0] + timedelta(minutes=30), hours[2]), "p2": (hours[2], hours[2] + 2 * H)}

    plain, _ = writable_runs(cells, spans, (hours[0], hours[0] + 4 * H), deduplicates=False)
    dedup, skipped = writable_runs(cells, spans, (hours[0], hours[0] + 4 * H), deduplicates=True)

    assert plain == [(hours[1], hours[0] + 4 * H)]
    # p1 began before h1, so its tokens may have hidden an h1 record: h1 is not written; h2 onward is
    assert dedup == [(hours[2], hours[0] + 4 * H)]
    assert skipped == {"an incomplete window cell": 1, "a deduplicated window cell straddles the start of its run": 1}


def test_external_destinations_are_not_written_when_the_hunts_hosts_contradict_its_networks():
    spec = SPEC_BY_ID["bl.ext_dest"]
    repo = _repo()
    _hunt(repo, hours=1, spec=spec, networks={"source": "configured", "digest": "network-a"})
    flow = TypedEvent(
        id="flow", family="net_flow", ts=START + timedelta(minutes=5), host="sensor",
        fields={"source.ip": fv("10.0.0.4", "fixture"), "destination.ip": fv("192.0.2.1", "fixture")},
        raw=[RawRef(target="host-index", native_id="flow", digest="raw-flow")], normalizer="fixture@1",
    )
    _sweep_cell(repo, [flow], START, START + H, playbook=ExternalDestinationBaseline())
    repo.audit("system", "hunt.sweep_summary", "hunt-a", {
        "finished": True, "complete": False, "partial_reasons": [], "stats": {},
        "internal_networks": {"outside": 1, "examples": ["198.51.100.7"]},
    })

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True)

    assert repo.baseline_segments() == []
    assert "outside the internal-network definition" in summary["specs"][spec.id]["reason"]


# ---- O1: the window material is released, or kept through one resume within a disk budget --------------------

def test_a_complete_hunt_releases_its_material_whatever_its_hours_wrote():
    repo = _repo()
    _hunt(repo, hours=1)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H, state="evaluated_partial")

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert summary["written"] == 0 and summary["material"]["kept"] is False
    assert repo.baseline_window_material_pairs("hunt-a") == []
    assert repo.baseline_window_retention("hunt-a") is None


def test_resume_then_finish_rewrites_with_the_new_citations_and_releases_the_material():
    repo = _repo()
    _hunt(repo, hours=1)
    cited = _event("cited", "/tmp/implant", 5)
    _sweep_cell(repo, [cited, _event("routine", "/usr/bin/id", 6)], START, START + H)

    first = _finish_partial_for_expansion(repo)
    old = repo.baseline_segments(statuses=["active"])[0]
    assert first["execution_state"] == "partial"
    assert {row["key"]["executable"] for row in repo.baseline_counts(old["id"])} == {"/tmp/implant", "/usr/bin/id"}

    # the resumed expansion publishes a finding that cites the implant, then the resumed hunt finishes
    _candidate(repo, cited)
    repo.claim_hunt("hunt-a", 600, resume=True)
    _finish_partial_for_expansion(repo)

    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert writer["stale"] == 1 and writer["written"] == 1
    assert next(row for row in repo.baseline_segments() if row["id"] == old["id"])["status"] == "stale"
    active = repo.baseline_segments(statuses=["active"])[0]
    assert {row["key"]["executable"] for row in repo.baseline_counts(active["id"])} == {"/usr/bin/id"}
    assert writer["material"]["kept"] is False
    assert repo.baseline_window_material_pairs("hunt-a") == []
    assert repo.baseline_window_retention("hunt-a") is None
    assert "resumed hunt finished" in repo.baseline_window_release("hunt-a", SPEC.id, "host-index")


def test_a_failed_baseline_stage_keeps_its_material_for_the_resumed_judgement():
    repo = _repo()
    _hunt(repo, hours=1)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True, baseline_finished=False)
    again = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True, baseline_finished=False)

    assert summary["material"]["kept"] and again["material"]["kept"]
    assert "resumed baseline stage" in summary["material"]["reason"]
    assert repo.baseline_window_material_pairs("hunt-a") == [(SPEC.id, "host-index")]


def _retained_hunt(repo, hunt_id, keys, *, minute=0):
    _hunt(repo, hours=1, hunt_id=hunt_id)
    events = [_event(f"{hunt_id}-{index}", f"/opt/{hunt_id}/tool-{index:04d}", minute) for index in range(keys)]
    _sweep_cell(repo, events, START, START + H, hunt_id=hunt_id)


def test_the_disk_budget_releases_the_oldest_retained_material_first():
    repo = _repo()
    for hunt_id in ("hunt-1", "hunt-2", "hunt-3"):
        _retained_hunt(repo, hunt_id, 50)
    size = repo.baseline_window_material_bytes("hunt-1")
    budget = 2 * size + size // 2
    clock = START + 10 * H
    for index, hunt_id in enumerate(("hunt-1", "hunt-2", "hunt-3")):
        summary = run_hunt_segment_writer(repo, hunt_id, hunt_partial=True, retain_budget_bytes=budget,
                                          now=clock + index * H)
        repo.set_hunt_state(hunt_id, "partial")
        # every hunt decides its complete hours before its material is settled
        assert summary["specs"][SPEC.id]["reason"] is None

    assert summary["material"]["kept"] is True
    assert summary["material"]["released_hunts"] == ["hunt-1"]
    assert summary["material"]["retained_bytes"] <= budget
    assert repo.baseline_window_material_pairs("hunt-1") == []
    assert "disk budget" in repo.baseline_window_release("hunt-1", SPEC.id, "host-index")
    assert [row["hunt_id"] for row in repo.baseline_window_retentions()] == ["hunt-2", "hunt-3"]


def test_material_larger_than_the_whole_budget_is_released_at_once():
    repo = _repo()
    _retained_hunt(repo, "hunt-1", 20)

    summary = run_hunt_segment_writer(repo, "hunt-1", hunt_partial=True, retain_budget_bytes=10)

    assert summary["written"] == 1
    assert summary["material"]["kept"] is False and "disk budget" in summary["material"]["reason"]
    assert repo.baseline_window_material_pairs("hunt-1") == []
    assert repo.baseline_window_retentions() == []


def test_material_no_finish_settled_is_charged_to_the_budget_and_released_oldest_first():
    repo = _repo()
    # a partial hunt finished before the retention ledger existed: its material has no charge
    _retained_hunt(repo, "legacy", 50)
    repo.set_hunt_state("legacy", "partial")
    # a completed hunt whose release was interrupted
    _retained_hunt(repo, "done", 5)
    repo.set_hunt_state("done", "completed_within_scope")
    _retained_hunt(repo, "hunt-new", 50)
    size = repo.baseline_window_material_bytes("hunt-new")

    summary = run_hunt_segment_writer(repo, "hunt-new", hunt_partial=True, retain_budget_bytes=size + size // 2,
                                      now=datetime.now(UTC))

    assert summary["material"]["released_hunts"] == ["legacy"]
    assert repo.baseline_window_material_pairs("done") == []
    assert repo.baseline_window_material_pairs("legacy") == []
    assert [row["hunt_id"] for row in repo.baseline_window_retentions()] == ["hunt-new"]


@pytest.mark.slow
def test_a_large_partial_hunt_writes_streams_and_releases_its_material_with_short_write_locks(monkeypatch, tmp_path):
    """Mission-scale shape: 48 hourly cells of 5,000 keys each (240,000 material rows) on a file store. The writer
    streams them into one segment, keeps them through one resume, and then releases them; no write transaction
    holds the lock for long, and nothing is held in memory per key."""
    import time

    from romulus.store import repo as repo_module
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    repo = Repo(make_engine(tmp_path / "large.db"))
    migrate(repo.engine)
    hours, keys = 48, 5_000
    _hunt(repo, hours=hours)
    for hour in range(hours):
        start = START + hour * H

        def counts(start=start, hour=hour):
            for index in range(keys):
                yield {"scope_kind": "host", "scope": f"host:web{index % 50:02d}", "key_id": f"k-{hour}-{index}",
                       "key_digest": f"d-{hour}-{index}", "key": {"executable": f"/opt/t{hour}/{index}"},
                       "bucket": start.replace(hour=0), "material_hour": start, "count": 1,
                       "first_ts": start, "last_ts": start}

        repo.save_baseline_window_cell("hunt-a", {
            "rule_id": SPEC.id, "version": SPEC.version, "target": "host-index",
            "partition": f"{start.isoformat()}/{(start + H).isoformat()}", "state": "evaluated_complete",
            "matched": 0, "evaluated": keys, "detail": {"reasons": []},
        }, (), counts=counts(), scope_hours=({"scope_kind": "host", "scope": f"host:web{index:02d}", "hour": start,
                                              "events": keys // 50} for index in range(50)),
            event_hours=[{"hour": start, "events": keys}])
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

    monkeypatch.setattr(repo_module, "write_txn", Timed)

    began = time.perf_counter()
    first = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True)
    written_in = time.perf_counter() - began
    segment = repo.baseline_segments(statuses=["active"])[0]
    assert first["written"] == 1 and (segment["start"], segment["end"]) == (START, START + hours * H)
    assert segment["events_total"] == hours * keys
    assert first["material"]["kept"] and first["material"]["bytes"] > 0
    repo.set_hunt_state("hunt-a", "partial")
    repo.claim_hunt("hunt-a", 600, resume=True)

    began = time.perf_counter()
    second = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True)
    released_in = time.perf_counter() - began

    assert second["material"]["kept"] is False
    assert repo.baseline_window_material_pairs("hunt-a") == []
    print(f"large writer: {hours * keys} rows written in {written_in:.1f}s, released in {released_in:.1f}s, "
          f"{len(holds)} write transactions, longest hold {max(holds):.3f}s")
    assert max(holds) < 2.0


def test_a_running_hunts_material_is_never_charged_or_released():
    repo = _repo()
    _retained_hunt(repo, "busy", 5)
    _retained_hunt(repo, "hunt-new", 5)

    run_hunt_segment_writer(repo, "hunt-new", hunt_partial=True, retain_budget_bytes=1)

    assert repo.baseline_window_material_pairs("busy") == [(SPEC.id, "host-index")]
    assert repo.baseline_window_retention("busy") is None


# ---- review corrections ------------------------------------------------------------------------------------

def test_budget_eviction_never_releases_a_leased_hunts_material():
    repo = _repo()
    _retained_hunt(repo, "busy", 50)
    run_hunt_segment_writer(repo, "busy", hunt_partial=True, now=datetime(2026, 3, 1, tzinfo=UTC))
    repo.set_hunt_state("busy", "partial")
    # resumed: it holds an active lease and its baseline stage may judge from this material
    repo.claim_hunt("busy", 600, resume=True)
    _hunt(repo, hours=1, hunt_id="other")
    _sweep_cell(repo, [_event("o1", "/usr/bin/x", 5)], START, START + H, hunt_id="other")
    size = repo.baseline_window_material_bytes("other")

    summary = run_hunt_segment_writer(repo, "other", hunt_partial=True, retain_budget_bytes=size + 10,
                                      now=datetime.now(UTC))

    assert summary["material"]["released_hunts"] == []
    assert summary["material"]["over_budget"] is True
    assert repo.baseline_window_material_pairs("busy") == [(SPEC.id, "host-index")]
    assert repo.baseline_window_release("busy", SPEC.id, "host-index") is None


def test_a_hunt_whose_material_alone_exceeds_the_budget_is_released_before_older_material_that_fits():
    repo = _repo()
    _retained_hunt(repo, "small", 10)
    run_hunt_segment_writer(repo, "small", hunt_partial=True, now=datetime(2026, 3, 1, tzinfo=UTC))
    repo.set_hunt_state("small", "partial")
    small = repo.baseline_window_material_bytes("small")
    _retained_hunt(repo, "huge", 400)

    summary = run_hunt_segment_writer(repo, "huge", hunt_partial=True, retain_budget_bytes=2 * small,
                                      now=datetime(2026, 3, 2, tzinfo=UTC))

    assert summary["material"]["kept"] is False and summary["material"]["released_hunts"] == []
    assert repo.baseline_window_material_pairs("huge") == []
    assert repo.baseline_window_material_pairs("small") == [(SPEC.id, "host-index")]


def test_a_refused_segment_costs_only_its_run_and_the_material_is_still_settled(monkeypatch):
    repo = _repo()
    _hunt(repo, hours=1)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)

    def collide(row, **_kwargs):
        raise ValueError(f"baseline segment {row['id']} exists with different content")

    monkeypatch.setattr(repo, "begin_baseline_segment", collide)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert summary["written"] == 0
    assert "1 hour(s) not written: segment refused" in summary["specs"][SPEC.id]["reason"]
    assert "exists with different content" in summary["specs"][SPEC.id]["reason"]
    assert summary["material"]["kept"] is False
    assert repo.baseline_window_material_pairs("hunt-a") == []


def test_an_interrupted_writer_still_charges_its_kept_material_to_the_budget(monkeypatch):
    import pytest as _pytest

    repo = _repo()
    _hunt(repo, hours=1)
    _sweep_cell(repo, [_event("a", "/usr/bin/id", 5)], START, START + H)

    def crash(*_args, **_kwargs):
        raise RuntimeError("killed mid-write")

    monkeypatch.setattr(repo, "append_baseline_segment_rows", crash)

    with _pytest.raises(RuntimeError):
        run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    retention = repo.baseline_window_retention("hunt-a")
    assert retention is not None and retention["bytes"] > 0 and "interrupted" in retention["reason"]
    assert repo.baseline_window_material_pairs("hunt-a") == [(SPEC.id, "host-index")]


def test_an_inapplicable_targets_empty_cell_from_a_partial_retrieval_is_never_written():
    repo = _repo()
    _hunt(repo, hours=2)
    for hour, complete in ((0, True), (1, False)):
        start = START + hour * H
        repo.save_baseline_window_cell("hunt-a", {
            "rule_id": SPEC.id, "version": SPEC.version, "target": "host-index",
            "partition": f"{start.isoformat()}/{(start + H).isoformat()}", "state": "not_applicable_no_events",
            "matched": 0, "evaluated": 0,
            "detail": {"reasons": [] if complete else ["source result cap reached"], "retrieval_complete": complete},
        }, ())

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert [(row["start"], row["end"]) for row in repo.baseline_segments(statuses=["active"])] == [
        (START, START + H)]
    assert "1 hour(s) not written: an incomplete window cell" in summary["specs"][SPEC.id]["reason"]


def test_a_hunt_segment_straddling_history_start_places_its_first_in_plan_record_like_the_lookback():
    """Records in hours 1 and 4 of a six-hour span; a later hunt's history is hours 2-6. The hunt-derived segment's
    first record overall (hour 1) is before the history: its first in-plan record is hour 4, as the lookback's."""
    events = [_event("e1", "/usr/bin/id", 70), _event("e4", "/usr/bin/id", 250)]
    hunt_repo = _repo()
    _hunt(hunt_repo, hours=6)
    for hour in range(6):
        _sweep_cell(hunt_repo, [event for event in events if START + hour * H <= event.ts < START + (hour + 1) * H],
                    START + hour * H, START + (hour + 1) * H)
    run_hunt_segment_writer(hunt_repo, "hunt-a", hunt_partial=False)
    lookback_repo = _repo()
    lookback_repo.create_hunt("build", {}, "manifest-build", "test")
    LookbackWriter(
        lookback_repo, FakeHistory(events), site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=50, records=100, seconds=10), now=lambda: START + 6 * H,
    ).fill(hunt_id="build", targets=["host-index"], start=START + 2 * H, end=START + 6 * H)

    coverages = []
    for repo in (hunt_repo, lookback_repo):
        later = _manifest()
        later["window"] = {"start": (START + 6 * H).isoformat(), "end": (START + 7 * H).isoformat()}
        repo.create_hunt("later", later, "manifest-later", "test")
        snapshot = SnapshotPlanner(repo).freeze(
            hunt_id="later", window_start=START + 6 * H, lookback=4 * H, min_live_hours=1, site="site-a",
            targets=["host-index"], specs=[SPEC],
        )
        coverage = snapshot["coverage"]["host-index|bl.exec_path"]
        coverages.append({name: coverage[name] for name in ("effective_start", "effective_hours",
                                                              "absent_before", "status")})

    assert coverages[0] == coverages[1] == {
        "effective_start": (START + 4 * H).isoformat(), "effective_hours": 2,
        "absent_before": (START + 4 * H).isoformat(), "status": "shortened",
    }
