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
            "partition": "window-cell",
            "state": state,
            "matched": 0,
            "evaluated": len(events),
            "detail": {"reasons": []},
        },
        (),
        counts=counter.count_rows(),
        scope_hours=counter.scope_hour_rows(),
    )


def test_partial_hunt_writes_no_segment_and_states_the_reason():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=False)

    assert repo.baseline_segments() == []
    assert summary == {
        "status": "skipped",
        "written": 0,
        "stale": 0,
        "max_write_seconds": 0.0,
        "specs": {SPEC.id: {"written": 0, "reason": "hunt is partial"}},
    }


def test_complete_hunt_writes_counts_without_cited_keys_and_records_exclusions():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    cited = _event("cited", "/tmp/implant", 5)
    routine = _event("routine", "/usr/bin/id", 65)
    _stage_cell(repo, [cited, routine])
    _candidate(repo, cited)

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)

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

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)

    assert repo.baseline_segments() == []
    assert summary["specs"][SPEC.id] == {
        "written": 0,
        "reason": "host-index: 1 incomplete window cell(s)",
    }


def test_split_parent_cell_is_control_state_and_complete_children_still_write():
    repo = _repo()
    repo.create_hunt("hunt-a", _manifest(), "manifest-a", "test")
    _stage_cell(repo, [_event("routine", "/usr/bin/id", 5)])
    repo.set_rule_cell(
        "hunt-a", SPEC.id, SPEC.version, "host-index", "parent", "split", 0, 0,
        {"reasons": ["partition split"]},
    )

    summary = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)

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
    assert writer["specs"][SPEC.id]["reason"] == "host-index: 1 incomplete window cell(s)"


def test_twin_hunts_reuse_content_id_and_a_revoked_generation_is_rebuilt():
    repo = _repo()
    event = _event("routine", "/usr/bin/id", 5)
    for hunt_id in ("hunt-a", "hunt-b"):
        repo.create_hunt(hunt_id, _manifest(), f"manifest-{hunt_id}", "test")
        _stage_cell(repo, [event], hunt_id=hunt_id)

    first = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)
    second = run_hunt_segment_writer(repo, "hunt-b", hunt_complete=True)

    assert first["written"] == 1 and second["written"] == 0
    original = repo.baseline_segments()[0]
    assert original["source_hunt_id"] == "hunt-a"

    repo.set_baseline_segment_status(original["id"], "revoked")
    rebuilt = run_hunt_segment_writer(repo, "hunt-b", hunt_complete=True)

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

    run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)
    old = repo.baseline_segments(statuses=["active"])[0]
    _candidate(repo, cited, hunt_id="hunt-b", candidate_id="finding-b")

    result = run_hunt_segment_writer(repo, "hunt-b", hunt_complete=True)

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
    run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)
    _candidate(repo, cited, hunt_id="hunt-b", candidate_id="finding-b")

    skipped = run_hunt_segment_writer(repo, "hunt-b", hunt_complete=False)
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
            "partition": "window-cell", "state": "evaluated_complete", "matched": 0,
            "evaluated": 1, "detail": {"reasons": []},
        }, (), counts=counter.count_rows(), scope_hours=counter.scope_hour_rows(),
    )
    _candidate(repo, child)

    result = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)

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
            "partition": "cell", "state": "evaluated_complete", "matched": 0,
            "evaluated": 2, "detail": {"reasons": []},
        }, (), counts=counter.count_rows(), scope_hours=counter.scope_hour_rows(),
    )
    run_hunt_segment_writer(hunt_repo, "hunt-a", hunt_complete=True)

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
    run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)
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
        "hunt-a", SPEC.id, SPEC.version, "host-index", "weeks", "evaluated_complete", 0, 672,
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
    monkeypatch.setattr(repo, "baseline_window_merged_counts", counts)
    monkeypatch.setattr(repo, "baseline_window_merged_scope_hours", hours)

    result = run_hunt_segment_writer(repo, "hunt-a", hunt_complete=True)

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
