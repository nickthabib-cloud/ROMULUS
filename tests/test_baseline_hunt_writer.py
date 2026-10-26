"""Hunt-derived baseline segments written only from complete sweep cells."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.baseline import HistoryFetch, HistoryPartition, HistoryPlan
from romulus.baseline.carry import CarryInStore, ParentExec, PendingResolver
from romulus.baseline.count import KeyCounter
from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.baseline_writer import run_hunt_segment_writer
from romulus.hunt.run import _finish
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_baseline_lookback import FakeHistory

START = datetime(2026, 2, 1, tzinfo=UTC)
END = START + timedelta(hours=2)
SPEC = SPEC_BY_ID["bl.exec_path"]


def _repo() -> Repo:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    return repo


def _manifest() -> dict:
    return {
        "window": {"start": START.isoformat(), "end": END.isoformat()},
        "targets": ["host-index"],
        "normalizer": "fixture@1",
        "baseline": {
            "site": "site-a",
            "specs": [{"id": SPEC.id, "version": SPEC.version, "key_version": SPEC.key_version}],
        },
    }


def _event(event_id: str, executable: str, minute: int) -> TypedEvent:
    return TypedEvent(
        id=event_id,
        family="process_exec",
        ts=START + timedelta(minutes=minute),
        host="web01",
        outcome=Outcome.success,
        fields={
            "process.executable": fv(executable, "fixture"),
            "process.exec_file.path": fv(executable, "fixture"),
            "process.user": fv("www-data", "fixture"),
        },
        raw=[RawRef(target="host-index", native_id=event_id, digest=f"raw-{event_id}")],
        normalizer="fixture@1",
    )


def _candidate(repo: Repo, event: TypedEvent, *, hunt_id: str = "hunt-a", candidate_id: str = "finding-a") -> None:
    repo.save_evidence(
        hunt_id,
        [event],
        {event.raw[0].key: {"event": event.id}},
        None,
    )
    repo.save_candidate({
        "id": candidate_id,
        "hunt_id": hunt_id,
        "rule_id": "host.fixture",
        "rule_version": "1",
        "claim": "fixture finding",
        "claim_type": "observed_action",
        "event_ids": [event.id],
        "context_event_ids": [],
        "predicate_fields": [],
        "entities": [],
        "ts": event.ts,
        "severity": "high",
        "confidence": "high",
        "lane": "high",
        "priority": 90.0,
        "priority_reasons": [],
        "gate_results": {},
        "benign_alternatives": [],
        "next_checks": [],
        "group_key": "fixture",
        "source_case_id": None,
        "source_anchor_id": None,
        "source_link_id": None,
    })


def _stage_cell(repo: Repo, events: list[TypedEvent], *, hunt_id: str = "hunt-a",
                state: str = "evaluated_complete") -> None:
    counter = KeyCounter("window-cell", SPEC, span=(START, END))
    for event in events:
        counter.consume(event, KeyContext())
    repo.save_baseline_window_cell(
        hunt_id,
        {
            "rule_id": SPEC.id,
            "version": SPEC.version,
            "target": "host-index",
            "partition": f"{START.isoformat()}/{END.isoformat()}",
            "state": state,
            "matched": 0,
            "evaluated": len(events),
            "detail": {"reasons": []},
        },
        (),
        counts=counter.material_count_rows(),
        scope_hours=counter.scope_hour_rows(),
        event_hours=counter.event_hour_rows(),
    )


def test_a_hunt_without_window_cells_writes_nothing_and_states_the_reason():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=True)

    assert repo.baseline_segments() == []
    assert summary["status"] == "complete" and summary["written"] == 0
    assert summary["specs"] == {SPEC.id: {"written": 0, "reason": "host-index: no window cells"}}


def test_complete_hunt_writes_counts_without_cited_keys_and_records_exclusions():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    cited = _event("cited", "/tmp/implant", 5)
    routine = _event("routine", "/usr/bin/id", 65)
    _stage_cell(repo, [cited, routine])
    _candidate(repo, cited)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segments = repo.baseline_segments(statuses=["active"])
    assert summary["written"] == 1 and len(segments) == 1
    segment = segments[0]
    assert segment["origin"] == "hunt" and segment["source_hunt_id"] == "hunt-a"
    assert segment["hunted"] == 1 and segment["excluded_keys"] == sorted(segment["excluded_keys"])
    assert len(segment["excluded_keys"]) == 2 and segment["exclusion_digest"] != "none"
    stored = list(repo.baseline_counts(segment["id"]))
    assert {row["key"]["executable"] for row in stored} == {"/usr/bin/id"}
    assert sum(row["count"] for row in stored) == 2


def test_complete_hunt_skips_a_spec_with_any_partial_cell_and_audits_the_reason():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)], state="evaluated_partial")

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert summary["specs"][SPEC.id] == {
        "written": 0,
        "reason": "host-index: 2 hour(s) not written: an incomplete window cell",
    }


def test_split_parent_cell_is_control_state_and_complete_children_still_write():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)])
    repo.set_rule_cell(
        "hunt-a", SPEC.id, SPEC.version, "host-index", "parent", "split", 0, 0,
        {"reasons": ["partition split"]},
    )

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert summary["written"] == 1
    assert len(repo.baseline_segments(statuses=["active"])) == 1


def test_finish_records_the_segment_writer_reason_in_the_baseline_audit():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    repo.set_hunt_state("hunt-a", "running")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)], state="evaluated_partial")

    result = _finish(
        repo, "hunt-a", {"status": "disabled", "stop_reason": ""},
        {"finished": True, "complete": True, "partial_reasons": [], "stats": {}},
        baseline_summary={"finished": True, "status": "complete", "stage_failed": False},
    )

    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert result["execution_state"] == "completed_within_scope"
    assert writer["specs"][SPEC.id]["reason"] == "host-index: 2 hour(s) not written: an incomplete window cell"


def test_twin_hunts_reuse_content_id_and_a_revoked_generation_is_rebuilt():
    repo = _repo()
    event = _event("routine", "/usr/bin/id", 5)
    for hunt_id in ("hunt-a", "hunt-b", "hunt-c"):
        repo.create_hunt(hunt_id, _manifest(), f"manifest-{hunt_id}", "test")
        _stage_cell(repo, [event], hunt_id=hunt_id)

    first = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    second = run_hunt_segment_writer(repo, "hunt-b", hunt_partial=False)

    assert first["written"] == 1 and second["written"] == 0
    original = repo.baseline_segments()[0]
    assert original["source_hunt_id"] == "hunt-a"

    repo.set_baseline_segment_status(original["id"], "revoked")
    rebuilt = run_hunt_segment_writer(repo, "hunt-c", hunt_partial=False)

    rows = repo.baseline_segments()
    assert rebuilt["written"] == 1
    assert [(row["id"], row["status"]) for row in rows] == [
        (original["id"], "revoked"),
        (f"{original['id']}-r1", "active"),
    ]


def test_later_overlapping_citation_stales_old_segment_and_union_excludes_the_key():
    repo = _repo()
    routine = _event("routine", "/usr/bin/id", 5)
    cited = _event("cited", "/tmp/implant", 65)
    for hunt_id in ("hunt-a", "hunt-b"):
        repo.create_hunt(hunt_id, _manifest(), f"manifest-{hunt_id}", "test")
        _stage_cell(repo, [routine, cited], hunt_id=hunt_id)

    run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    old = repo.baseline_segments(statuses=["active"])[0]
    _candidate(repo, cited, hunt_id="hunt-b", candidate_id="finding-b")

    result = run_hunt_segment_writer(repo, "hunt-b", hunt_partial=False)

    rows = repo.baseline_segments()
    assert next(row for row in rows if row["id"] == old["id"])["status"] == "stale"
    active = next(row for row in rows if row["status"] == "active")
    assert result["stale"] == 1
    assert {row["key"]["executable"] for row in repo.baseline_counts(active["id"])} == {"/usr/bin/id"}


def test_exclusion_union_is_scoped_to_the_spec_and_key_versions():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    repo.replace_baseline_hunt_exclusions(
        "hunt-a", site="site-a", start=START, end=END,
        exclusions={("host-index", SPEC.id): {"old-key"}},
        spec_versions={SPEC.id: (SPEC.version, SPEC.key_version)},
    )

    common = {
        "site": "site-a", "target": "host-index", "spec_id": SPEC.id,
        "start": START, "end": END,
    }
    assert repo.baseline_exclusion_keys(
        **common, spec_version=SPEC.version, key_version=SPEC.key_version,
    ) == ["old-key"]
    assert repo.baseline_exclusion_keys(
        **common, spec_version="future", key_version=SPEC.key_version,
    ) == []


def test_partial_later_hunt_stales_the_old_segment_and_lookback_refills_with_union_exclusions():
    repo = _repo()
    routine = _event("routine", "/usr/bin/id", 5)
    cited = _event("cited", "/tmp/implant", 65)
    for hunt_id in ("hunt-a", "hunt-b"):
        repo.create_hunt(hunt_id, _manifest(), f"manifest-{hunt_id}", "test")
    _stage_cell(repo, [routine, cited], hunt_id="hunt-a")
    run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    _candidate(repo, cited, hunt_id="hunt-b", candidate_id="finding-b")

    skipped = run_hunt_segment_writer(repo, "hunt-b", hunt_partial=True)
    assert skipped["stale"] == 1
    assert repo.baseline_segments(statuses=["active"]) == []

    result = LookbackWriter(
        repo, FakeHistory([routine, cited]), site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=20, records=20, seconds=20), now=lambda: END,
    ).fill(hunt_id="hunt-b", targets=["host-index"], start=START, end=END)

    assert result.complete == 2 and result.gaps == ()
    active = repo.baseline_segments(statuses=["active"])
    assert len(active) == 2 and all(row["excluded_keys"] for row in active)
    stored = [count for row in active for count in repo.baseline_counts(row["id"])]
    assert {row["key"]["executable"] for row in stored} == {"/usr/bin/id"}


def test_exec_pair_citation_resolves_against_the_network_index_carry_before_exclusion():
    repo = _repo()
    spec = SPEC_BY_ID["bl.exec_pair"]
    manifest = _manifest()
    manifest["baseline"]["specs"] = [
        {"id": spec.id, "version": spec.version, "key_version": spec.key_version},
    ]
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    child = _event("child", "/bin/curl", 5)
    child.fields.update({
        "process.pid": fv(20, "fixture"), "process.ppid": fv(10, "fixture"),
        "host.boot.id": fv("boot-1", "fixture"),
    })
    carry = CarryInStore(repo, "hunt-a").for_target("host-index", horizon=END)
    carry.observe_rows([
        ParentExec("web01", "boot-1", 10, START - timedelta(minutes=5),
                   "/usr/sbin/sshd", 1, "parent"),
    ])
    carry.mark_observed(START - timedelta(hours=1), END)
    pending = spec.keys(child, KeyContext())
    resolution = PendingResolver(carry, spec).resolve(pending)
    assert resolution.reason is None
    counter = KeyCounter("window-cell", spec, span=(START, END))
    counter.add_keys(child.ts, resolution.keys)
    repo.save_baseline_window_cell(
        "hunt-a", {
            "rule_id": spec.id, "version": spec.version, "target": "host-index",
            "partition": f"{START.isoformat()}/{END.isoformat()}", "state": "evaluated_complete", "matched": 0,
            "evaluated": 1, "detail": {"reasons": []},
        }, (), counts=counter.material_count_rows(), scope_hours=counter.scope_hour_rows(),
        # the sweep counter that consumed the child records its hour
        event_hours=[{"hour": START, "events": 1}],
    )
    _candidate(repo, child)

    result = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert result["written"] == 1
    assert len(segment["excluded_keys"]) == 1
    assert list(repo.baseline_counts(segment["id"])) == []


def test_hunt_and_lookback_writers_are_equivalent_at_clamped_hour_edges():
    hour_end = START + timedelta(hours=1)
    early = _event("early", "/bin/early", 0).model_copy(update={"ts": START - timedelta(seconds=1)})
    late = _event("late", "/bin/late", 0).model_copy(update={"ts": hour_end + timedelta(seconds=1)})

    hunt_repo = _repo()
    manifest = _manifest()
    manifest["window"]["end"] = hour_end.isoformat()
    hunt_repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    counter = KeyCounter("cell", SPEC, span=(START, hour_end))
    for event in (early, late):
        counter.consume(event, KeyContext())
    hunt_repo.save_baseline_window_cell(
        "hunt-a", {
            "rule_id": SPEC.id, "version": SPEC.version, "target": "host-index",
            "partition": f"{START.isoformat()}/{hour_end.isoformat()}", "state": "evaluated_complete",
            "matched": 0,
            "evaluated": 2, "detail": {"reasons": []},
        }, (), counts=counter.material_count_rows(), scope_hours=counter.scope_hour_rows(),
        event_hours=counter.event_hour_rows(),
    )
    run_hunt_segment_writer(hunt_repo, "hunt-a", hunt_partial=False)

    class SkewedHistory:
        def plan(self, target, start, end, *, query_budget):
            return HistoryPlan((HistoryPartition(target, start, end, 2, "skewed"),), 1, "complete", ())

        def fetch(self, partition, **_kwargs):
            return HistoryFetch((early, late), "complete", (), 2)

    lookback_repo = _repo()
    lookback_repo.create_hunt("build", {}, "manifest-build", "test")
    result = LookbackWriter(
        lookback_repo, SkewedHistory(), site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=5, records=5, seconds=5), now=lambda: hour_end,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=hour_end)

    hunt_segment = hunt_repo.baseline_segments(statuses=["active"])[0]
    lookback_segment = lookback_repo.baseline_segments(statuses=["active"])[0]
    without_id = lambda row: {key: value for key, value in row.items() if key != "segment_id"}
    assert result.complete == 1 and result.gaps == ()
    assert [without_id(row) for row in hunt_repo.baseline_counts(hunt_segment["id"])] == [
        without_id(row) for row in lookback_repo.baseline_counts(lookback_segment["id"])
    ]
    assert [without_id(row) for row in hunt_repo.baseline_scope_hours(hunt_segment["id"])] == [
        without_id(row) for row in lookback_repo.baseline_scope_hours(lookback_segment["id"])
    ]


def test_second_hunt_uses_the_first_hunts_segment_without_history_queries():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)])
    run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    repo.create_hunt("hunt-b", {}, "manifest-b", "test")
    source = FakeHistory([_event("should-not-load", "/tmp/no", 5)])

    result = LookbackWriter(
        repo, source, site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), now=lambda: END,
    ).fill(hunt_id="hunt-b", targets=["host-index"], start=START, end=END)
    snapshot = SnapshotPlanner(repo).freeze(
        hunt_id="hunt-b", window_start=END, lookback=timedelta(hours=2), min_live_hours=1,
        site="site-a", targets=["host-index"], specs=[SPEC],
    )

    assert result.gaps == () and source.plans == [] and source.fetches == []
    assert snapshot["status"] == "resolved"
    assert snapshot["segment_ids"] == [repo.baseline_segments(statuses=["active"])[0]["id"]]


def test_weeks_long_hunt_streams_merged_rows_without_using_list_readers(monkeypatch):
    weeks_end = START + timedelta(days=28)
    manifest = _manifest()
    manifest["window"]["end"] = weeks_end.isoformat()
    repo = _repo()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    repo.set_rule_cell(
        "hunt-a", SPEC.id, SPEC.version, "host-index", f"{START.isoformat()}/{weeks_end.isoformat()}",
        "evaluated_complete", 0, 672,
        {"reasons": []},
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("hunt writer used the materializing cell reader")

    def counts(*_args, **_kwargs):
        for index in range(672):
            instant = START + timedelta(hours=index)
            yield {
                "scope_kind": "host", "scope": f"host:{index:04d}",
                "key_id": f"key-{index:04d}", "key_digest": f"digest-{index:04d}",
                "key": {"executable": f"/bin/tool-{index:04d}"},
                "bucket": instant.replace(hour=0), "count": 1,
                "first_ts": instant, "last_ts": instant,
            }

    def hours(*_args, **_kwargs):
        for index in range(672):
            instant = START + timedelta(hours=index)
            yield {"scope_kind": "host", "scope": f"host:{index:04d}", "hour": instant, "events": 1}

    monkeypatch.setattr(repo, "baseline_window_counts", forbidden)
    monkeypatch.setattr(repo, "baseline_window_scope_hours", forbidden)
    def event_hours(*_args, **_kwargs):
        for index in range(672):
            yield {"hour": START + timedelta(hours=index), "events": 1}

    monkeypatch.setattr(repo, "baseline_window_merged_counts", counts)
    monkeypatch.setattr(repo, "baseline_window_merged_scope_hours", hours)
    monkeypatch.setattr(repo, "baseline_window_merged_event_hours", event_hours)

    result = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert result["written"] == 1 and result["max_write_seconds"] < 3
    assert sum(1 for _ in repo.baseline_counts(segment["id"])) == 672
    assert sum(1 for _ in repo.baseline_scope_hours(segment["id"])) == 672


def test_merged_window_rows_keyset_page_past_many_scopes():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")

    def counts():
        for index in range(5_001):
            yield {
                "scope_kind": "host", "scope": f"host:{index:05d}",
                "key_id": f"key-{index:05d}", "key_digest": f"digest-{index:05d}",
                "key": {"executable": f"/bin/tool-{index:05d}"}, "bucket": START,
                "count": 1, "first_ts": START, "last_ts": START,
            }

    def hours():
        for index in range(5_001):
            yield {
                "scope_kind": "host", "scope": f"host:{index:05d}",
                "hour": START, "events": 1,
            }

    repo.save_baseline_window_cell(
        "hunt-a", {
            "rule_id": SPEC.id, "version": SPEC.version, "target": "host-index",
            "partition": "large-cell", "state": "evaluated_complete", "matched": 0,
            "evaluated": 5_001, "detail": {"reasons": []},
        }, (), counts=counts(), scope_hours=hours(),
    )

    merged_counts = list(repo.baseline_window_merged_counts(
        "hunt-a", SPEC.id, "host-index", page_size=137,
    ))
    merged_hours = list(repo.baseline_window_merged_scope_hours(
        "hunt-a", SPEC.id, "host-index", page_size=137,
    ))
    assert len(merged_counts) == len(merged_hours) == 5_001
    assert merged_counts[0]["scope"] == "host:00000" and merged_counts[-1]["scope"] == "host:05000"


def _cell(repo: Repo, events: list[TypedEvent], start: datetime, end: datetime, *, spec=SPEC,
          hunt_id: str = "hunt-a") -> None:
    counter = KeyCounter("cell", spec, span=(start, end))
    for event in events:
        counter.consume(event, KeyContext())
    repo.save_baseline_window_cell(
        hunt_id, {
            "rule_id": spec.id, "version": spec.version, "target": "host-index",
            "partition": f"{start.isoformat()}/{end.isoformat()}", "state": "evaluated_complete",
            "matched": 0, "evaluated": len(events), "detail": {"reasons": []},
        }, (), counts=counter.material_count_rows(), scope_hours=counter.scope_hour_rows(),
        event_hours=counter.event_hour_rows(),
    )


def _half_hour_hunt(repo: Repo) -> None:
    end = START + timedelta(hours=2, minutes=30)
    manifest = _manifest()
    manifest["window"]["end"] = end.isoformat()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    repo.set_hunt_state("hunt-a", "running")
    _cell(repo, [_event("first", "/usr/bin/id", 5)], START, START + timedelta(hours=1))
    _cell(repo, [_event("second", "/usr/bin/w", 70)], START + timedelta(hours=1), START + timedelta(hours=2))
    _cell(repo, [_event("tail", "/usr/bin/tail-hour", 135)], START + timedelta(hours=2), end)


def _finish_complete(repo: Repo) -> dict:
    return _finish(
        repo, "hunt-a", {"status": "disabled", "stop_reason": ""},
        {"finished": True, "complete": True, "partial_reasons": [], "stats": {}},
        baseline_summary={"finished": True, "status": "complete", "stage_failed": False},
    )


def test_a_window_ending_on_the_half_hour_writes_its_whole_hours_and_leaves_the_hunt_complete():
    repo = _repo()
    _half_hour_hunt(repo)

    result = _finish_complete(repo)

    assert result["execution_state"] == "completed_within_scope"
    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert writer["written"] == 1 and writer["specs"][SPEC.id]["reason"] is None
    segment = repo.baseline_segments(statuses=["active"])[0]
    assert (segment["start"], segment["end"]) == (START, START + timedelta(hours=2))
    assert segment["events_total"] == 2
    assert {row["key"]["executable"] for row in repo.baseline_counts(segment["id"])} == {
        "/usr/bin/id", "/usr/bin/w",
    }
    assert max(row["hour"] for row in repo.baseline_scope_hours(segment["id"])) == START + timedelta(hours=1)


def test_cells_straddling_hour_edges_still_write_their_per_hour_material():
    repo = _repo()
    end = START + timedelta(hours=2, minutes=30)
    manifest = _manifest()
    manifest["window"]["end"] = end.isoformat()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    _cell(repo, [_event("first", "/usr/bin/id", 5)], START, START + timedelta(hours=1))
    _cell(repo, [_event("middle", "/usr/bin/w", 70)], START + timedelta(hours=1), START + timedelta(minutes=90))
    _cell(repo, [_event("late", "/usr/bin/late", 100)], START + timedelta(minutes=90), end)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert summary["written"] == 1
    assert (segment["start"], segment["end"]) == (START, START + timedelta(hours=2))
    assert segment["events_total"] == 3
    assert {row["key"]["executable"] for row in repo.baseline_counts(segment["id"])} == {
        "/usr/bin/id", "/usr/bin/w", "/usr/bin/late",
    }


def test_one_non_aligned_cell_writes_all_whole_hours_inside_it():
    repo = _repo()
    end = START + timedelta(hours=2, minutes=30)
    manifest = _manifest()
    manifest["window"]["end"] = end.isoformat()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    _cell(repo, [_event("only", "/usr/bin/id", 5)], START, end)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert summary["written"] == 1 and summary["specs"][SPEC.id]["reason"] is None
    assert (segment["start"], segment["end"]) == (START, START + timedelta(hours=2))
    assert segment["events_total"] == 1
    assert {row["key"]["executable"] for row in repo.baseline_counts(segment["id"])} == {"/usr/bin/id"}


def test_non_aligned_cell_excludes_edge_hours_field_by_field():
    window_start, window_end = START + timedelta(minutes=30), START + timedelta(hours=3, minutes=30)
    manifest = _manifest()
    manifest["window"] = {"start": window_start.isoformat(), "end": window_end.isoformat()}
    repo = _repo()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    events = [
        _event("left-edge", "/bin/left", 40),
        _event("inside-a", "/bin/a", 70),
        _event("inside-b", "/bin/b", 130),
        _event("right-edge", "/bin/right", 200),
    ]
    _cell(repo, events, window_start, window_end)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert summary["written"] == 1
    assert (segment["start"], segment["end"], segment["events_total"]) == (
        START + timedelta(hours=1), START + timedelta(hours=3), 2,
    )
    assert {row["key"]["executable"] for row in repo.baseline_counts(segment["id"])} == {
        "/bin/a", "/bin/b",
    }
    assert {row["hour"] for row in repo.baseline_scope_hours(segment["id"])} == {
        START + timedelta(hours=1), START + timedelta(hours=2),
    }


def test_deduplicated_token_crossing_a_clipped_left_edge_declines_the_segment():
    spec = SPEC_BY_ID["bl.ext_dest"]
    window_start = START + timedelta(minutes=30)
    manifest = _manifest()
    manifest["window"] = {"start": window_start.isoformat(), "end": END.isoformat()}
    manifest["baseline"]["specs"] = [
        {"id": spec.id, "version": spec.version, "key_version": spec.key_version},
    ]
    manifest["internal_networks"] = {"source": "configured", "digest": "network-a"}
    repo = _repo()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")

    def dns(event_id: str, minute: int, role: str) -> TypedEvent:
        answer = role == "answer"
        return TypedEvent(
            id=event_id, family="dns_query", ts=START + timedelta(minutes=minute), host="sensor",
            fields={
                "dns.type": fv(role, "fixture"),
                "dns.version": fv(3, "fixture"),
                "dns.id": fv(7, "fixture"),
                "dns.question.name": fv("www.example.com", "fixture"),
                "source.ip": fv("10.0.0.53" if answer else "10.0.0.4", "fixture"),
                "destination.ip": fv("10.0.0.4" if answer else "10.0.0.53", "fixture"),
                "source.port": fv(53 if answer else 40000, "fixture"),
                "destination.port": fv(40000 if answer else 53, "fixture"),
                "suricata.flow_id": fv(99, "fixture"),
            },
            raw=[RawRef(target="host-index", native_id=event_id, digest=f"raw-{event_id}")],
            normalizer="fixture@1",
        )

    _cell(repo, [dns("edge-query", 40, "query"), dns("inside-answer", 70, "answer")],
          window_start, END, spec=spec)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert "deduplicated window cell straddles" in summary["specs"][spec.id]["reason"]


def test_deduplicated_bucket_split_across_complete_cells_merges_tokens_per_hour():
    spec = SPEC_BY_ID["bl.ext_dest"]
    manifest = _manifest()
    manifest["baseline"]["specs"] = [
        {"id": spec.id, "version": spec.version, "key_version": spec.key_version},
    ]
    manifest["internal_networks"] = {"source": "configured", "digest": "network-a"}
    repo = _repo()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")

    def dns(event_id: str, minute: int, role: str) -> TypedEvent:
        answer = role == "answer"
        return TypedEvent(
            id=event_id, family="dns_query", ts=START + timedelta(minutes=minute), host="sensor",
            fields={
                "dns.type": fv(role, "fixture"), "dns.version": fv(3, "fixture"),
                "dns.id": fv(7, "fixture"), "dns.question.name": fv("www.example.com", "fixture"),
                "source.ip": fv("10.0.0.53" if answer else "10.0.0.4", "fixture"),
                "destination.ip": fv("10.0.0.4" if answer else "10.0.0.53", "fixture"),
                "source.port": fv(53 if answer else 40000, "fixture"),
                "destination.port": fv(40000 if answer else 53, "fixture"),
                "suricata.flow_id": fv(99, "fixture"),
            },
            raw=[RawRef(target="host-index", native_id=event_id, digest=f"raw-{event_id}")],
            normalizer="fixture@1",
        )

    middle = START + timedelta(hours=1)
    _cell(repo, [dns("query", 59, "query")], START, middle, spec=spec)
    _cell(repo, [dns("answer", 61, "answer")], middle, END, spec=spec)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    # Every cell of the day bucket inside the span is complete, so the tokens merge per hour: the transaction's
    # query (hour 0) and answer (hour 1) count once in each hour, as hourly lookback counters count them.
    segment = repo.baseline_segments(statuses=["active"])[0]
    assert summary["specs"][spec.id]["reason"] is None
    assert [row["count"] for row in repo.baseline_counts(segment["id"])] == [2]


def test_legacy_unplaced_count_spanning_a_clipped_edge_declines_the_segment():
    from romulus.store import schema

    window_start = START + timedelta(minutes=30)
    manifest = _manifest()
    manifest["window"] = {"start": window_start.isoformat(), "end": END.isoformat()}
    repo = _repo()
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    events = [_event("edge", "/usr/bin/id", 40), _event("inside", "/usr/bin/id", 70)]
    counter = KeyCounter("cell", SPEC, span=(window_start, END))
    for event in events:
        counter.consume(event, KeyContext())
    repo.save_baseline_window_cell(
        "hunt-a", {
            "rule_id": SPEC.id, "version": SPEC.version, "target": "host-index",
            "partition": f"{window_start.isoformat()}/{END.isoformat()}",
            "state": "evaluated_complete", "matched": 0, "evaluated": 2, "detail": {"reasons": []},
        }, (), counts=counter.count_rows(), scope_hours=counter.scope_hour_rows(),
        event_hours=counter.event_hour_rows(),
    )
    with repo.engine.begin() as connection:
        connection.execute(schema.baseline_window_count.update().values(material_hour=None))

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert "legacy window count material has no hour" in summary["specs"][SPEC.id]["reason"]


def test_a_writer_failure_is_stated_in_the_baseline_summary_and_never_makes_the_hunt_partial(monkeypatch):
    from romulus.hunt import run as hunt_run

    def broken(*_args, **_kwargs):
        raise RuntimeError("segment store unavailable")

    monkeypatch.setattr(hunt_run, "run_hunt_segment_writer", broken)
    repo = _repo()
    _half_hour_hunt(repo)

    result = _finish_complete(repo)

    assert result["execution_state"] == "completed_within_scope"
    assert result["partial_reasons"] == []
    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert writer["status"] == "failed" and "segment store unavailable" in writer["reason"]


def _set_context(repo: Repo, ids: list[str]) -> None:
    from romulus.store import schema

    with repo.engine.begin() as connection:
        connection.execute(schema.candidate.update().where(schema.candidate.c.id == "finding-a").values(
            context_event_ids=ids))


def test_a_findings_context_records_are_excluded_from_the_segment():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    subject, context = _event("subject", "/tmp/implant", 5), _event("ctxrec", "/tmp/dropper", 4)
    _stage_cell(repo, [subject, context, _event("routine", "/usr/bin/id", 6)])
    repo.save_evidence("hunt-a", [context], {context.raw[0].key: {"event": context.id}}, None)
    _candidate(repo, subject)
    _set_context(repo, ["ctxrec"])

    run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    segment = repo.baseline_segments(statuses=["active"])[0]
    assert {row["key"]["executable"] for row in repo.baseline_counts(segment["id"])} == {"/usr/bin/id"}
    assert len(segment["excluded_keys"]) == 4


def test_an_unresolvable_exec_pair_citation_blocks_the_segment_rather_than_risk_its_key():
    repo = _repo()
    spec = SPEC_BY_ID["bl.exec_pair"]
    manifest = _manifest()
    manifest["baseline"]["specs"] = [{"id": spec.id, "version": spec.version, "key_version": spec.key_version}]
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    child = _event("child", "/bin/curl", 5)
    child.fields.update({
        "process.pid": fv(20, "fixture"), "process.ppid": fv(10, "fixture"),
        "host.boot.id": fv("boot-1", "fixture"),
    })
    _cell(repo, [], START, END, spec=spec)
    _candidate(repo, child)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert summary["written"] == 0
    assert "cited record child has no resolvable key" in summary["specs"][spec.id]["reason"]


def test_a_cited_record_that_is_not_retained_blocks_every_segment():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    cited = _event("cited", "/tmp/implant", 5)
    _stage_cell(repo, [cited, _event("routine", "/usr/bin/id", 6)])
    _candidate(repo, cited)
    _set_context(repo, ["never-stored"])

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert "not retained" in summary["specs"][SPEC.id]["reason"]


def test_external_destination_segments_wait_for_a_configured_internal_network():
    repo = _repo()
    spec = SPEC_BY_ID["bl.ext_dest"]
    manifest = _manifest()
    manifest["baseline"]["specs"] = [{"id": spec.id, "version": spec.version, "key_version": spec.key_version}]
    manifest["internal_networks"] = {"source": "default", "digest": "rfc1918"}
    repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    _cell(repo, [], START, END, spec=spec)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert repo.baseline_segments() == []
    assert summary["specs"][spec.id]["reason"] == "host-index: internal networks not configured for this site"


def test_external_destination_hunt_segments_are_bound_end_to_end_to_the_network_digest():
    spec = SPEC_BY_ID["bl.ext_dest"]
    segment_ids = []
    for digest in ("network-a", "network-b"):
        repo = _repo()
        manifest = _manifest()
        manifest["baseline"]["specs"] = [
            {"id": spec.id, "version": spec.version, "key_version": spec.key_version},
        ]
        manifest["internal_networks"] = {"source": "configured", "digest": digest}
        repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
        event = TypedEvent(
            id="flow", family="net_flow", ts=START + timedelta(minutes=5), host="sensor",
            fields={
                "source.ip": fv("10.0.0.4", "fixture"),
                "destination.ip": fv("192.0.2.1", "fixture"),
            }, raw=[RawRef(target="host-index", native_id="flow", digest="raw-flow")],
            normalizer="fixture@1",
        )
        counter = KeyCounter("window-cell", spec, span=(START, END))
        counter.consume(event, KeyContext())
        repo.save_baseline_window_cell(
            "hunt-a",
            {
                "rule_id": spec.id, "version": spec.version, "target": "host-index",
                "partition": f"{START.isoformat()}/{END.isoformat()}", "state": "evaluated_complete",
                "matched": 0, "evaluated": 1, "detail": {"reasons": []},
            },
            (), counts=counter.count_rows(), scope_hours=counter.scope_hour_rows(),
            event_hours=counter.event_hour_rows(),
        )

        assert run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)["written"] == 1
        segment = repo.baseline_segments(statuses=["active"])[0]
        assert segment["network_digest"] == digest
        segment_ids.append(segment["id"])

    assert segment_ids[0] != segment_ids[1]


def test_window_material_is_released_after_the_decision_and_kept_through_a_crash(monkeypatch):
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)])

    def crash(*_args, **_kwargs):
        raise RuntimeError("killed mid-write")

    real_append = repo.append_baseline_segment_rows
    monkeypatch.setattr(repo, "append_baseline_segment_rows", crash)
    try:
        run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    except RuntimeError:
        pass
    assert repo.baseline_window_counts("hunt-a", SPEC.id, "host-index")
    assert repo.baseline_window_release("hunt-a", SPEC.id, "host-index") is None
    monkeypatch.setattr(repo, "append_baseline_segment_rows", real_append)

    resumed = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert resumed["written"] == 1
    assert resumed["material"]["kept"] is False
    assert repo.baseline_window_counts("hunt-a", SPEC.id, "host-index") == []
    assert repo.baseline_window_scope_hours("hunt-a", SPEC.id, "host-index") == []
    assert repo.baseline_window_release("hunt-a", SPEC.id, "host-index") == (
        "the hunt finished complete and its segment writer ran")
    again = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)
    assert again["written"] == 0 and "released earlier" in again["specs"][SPEC.id]["reason"]


def test_a_release_interrupted_after_its_marker_never_writes_from_the_remainder():
    from romulus.store import schema

    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5), _event("other", "/usr/bin/w", 6)])
    with repo.engine.begin() as connection:
        connection.execute(schema.baseline_window_release.insert().values(
            hunt_id="hunt-a", spec_id=SPEC.id, target="host-index", reason="segment written"))

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_partial=False)

    assert summary["written"] == 0 and repo.baseline_segments() == []
    assert repo.baseline_window_counts("hunt-a", SPEC.id, "host-index") == []


def test_a_multi_hour_cell_writes_what_hourly_lookback_writes_for_records_typed_inside_it():
    # The window counter clamps a record into its cell, the lookback into its hour. For a record typed inside its
    # cell (every exec: its typed time is the retrieval time) both give the same day-bucket counts and scope
    # hours. A record typed outside its multi-hour cell is placed at the cell's nearest edge, which can be up to
    # the cell's width from where an hourly read places it; its count moves only if that crosses a day boundary.
    two_hours = START + timedelta(hours=2)
    events = [_event("a", "/usr/bin/id", 10), _event("b", "/usr/bin/id", 70), _event("c", "/usr/bin/w", 100)]
    hunt_repo = _repo()
    manifest = _manifest()
    manifest["window"]["end"] = two_hours.isoformat()
    hunt_repo.create_hunt("hunt-a", manifest, "manifest-a", "test")
    _cell(hunt_repo, events, START, two_hours)
    run_hunt_segment_writer(hunt_repo, "hunt-a", hunt_partial=False)

    lookback_repo = _repo()
    lookback_repo.create_hunt("build", {}, "manifest-build", "test")
    LookbackWriter(
        lookback_repo, FakeHistory(events), site="site-a", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), now=lambda: two_hours,
    ).fill(hunt_id="build", targets=["host-index"], start=START, end=two_hours)

    hunt_segment = hunt_repo.baseline_segments(statuses=["active"])[0]
    lookback_segments = lookback_repo.baseline_segments(statuses=["active"])
    merged: dict[tuple, int] = {}
    for segment in lookback_segments:
        for row in lookback_repo.baseline_counts(segment["id"]):
            key = (row["scope"], row["key_digest"], row["bucket"])
            merged[key] = merged.get(key, 0) + row["count"]
    assert sorted((row["scope"], row["key_digest"], row["bucket"], row["count"])
                  for row in hunt_repo.baseline_counts(hunt_segment["id"])) == sorted(
        (*key, count) for key, count in merged.items())
    hours = lambda rows: sorted((row["scope"], row["hour"], row["events"]) for row in rows)
    assert hours(hunt_repo.baseline_scope_hours(hunt_segment["id"])) == hours(
        row for segment in lookback_segments for row in lookback_repo.baseline_scope_hours(segment["id"]))


def test_staleness_marking_over_thousands_of_overlapping_segments_holds_the_write_lock_briefly(
        monkeypatch, tmp_path):
    import time

    from romulus.store import repo as repo_module
    from romulus.store import schema

    repo = Repo(make_engine(tmp_path / "stale.db"))
    migrate(repo.engine)
    hours = 5_000
    begin = START - timedelta(hours=hours)
    with repo.engine.begin() as connection:
        connection.execute(schema.baseline_segment.insert(), [{
            "id": f"seg-{index:05d}", "site": "site-a", "target": "host-index", "spec_id": SPEC.id,
            "spec_version": SPEC.version, "key_version": SPEC.key_version, "normalizer": "fixture@1",
            "start": begin + timedelta(hours=index), "end": begin + timedelta(hours=index + 1),
            "bucket": "day", "origin": "lookback", "source_hunt_id": None, "built_by_hunt_id": None,
            "exclusion_digest": "none", "network_digest": None, "excluded_keys": [], "hunted": 0,
            "events_total": 1, "rows_digest": "fixture", "status": "active", "created_at": START,
        } for index in range(hours)])
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    repo.replace_baseline_hunt_exclusions(
        "hunt-a", site="site-a", start=begin, end=START,
        exclusions={("host-index", SPEC.id): {f"cited-{index}" for index in range(200)}},
        spec_versions={SPEC.id: (SPEC.version, SPEC.key_version)},
    )
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

    stale = repo.stale_baseline_segments_for_exclusions(site="site-a", start=begin, end=START)

    assert stale == hours
    assert len(holds) == hours // 500
    print(f"staleness: {hours} segments, {len(holds)} write transactions, longest hold {max(holds):.3f}s")
    assert max(holds) < 2.0
    assert {row["status"] for row in repo.baseline_segments()} == {"stale"}
