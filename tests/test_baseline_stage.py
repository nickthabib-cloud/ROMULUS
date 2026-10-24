"""Post-packet baseline judgement, publication, coverage, and resume semantics."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.protocol import HistoryFetch, HistoryPartition, HistoryPlan
from romulus.baseline.spec import SPEC_BY_ID
from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import run as hunt_run
from romulus.hunt.baseline_stage import BASELINE_CITATION_CAP, run_baseline_stage
from romulus.hunt.manifest import build_manifest
from romulus.hunt.packets import PACKET_NORMALIZER
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2026, 1, 8, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(hours=1))
SPEC = SPEC_BY_ID["bl.exec_path"]


class EmptyHistory:
    def __init__(self, state="complete", reason=""):
        self.state, self.reason = state, reason
        self.plans = 0

    def plan(self, target, start, end, *, query_budget):
        self.plans += 1
        if self.state != "complete":
            return HistoryPlan((), 1, self.state, (self.reason,))
        return HistoryPlan((HistoryPartition(target, start, end, 0, start.isoformat()),), 1, "complete", ())

    def fetch(self, partition, *, record_budget=None, query_budget=None, deadline=None):
        return HistoryFetch((), "complete", (), 0, 0)


def _manifest(*, spec_ids=(SPEC.id,), configured=True, budget=None, targets=("host-index",)):
    return {
        "style": "broad", "original_input": {}, "targets": list(targets),
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "source_profiles": {},
        "internal_networks": {
            "source": "configured" if configured else "default",
            "internal": ["10.0.0.0/8"] if configured else ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "external": [], "digest": "fixture",
        },
        "baseline": {
            "plan_version": "baseline-plan@1", "site": "site", "history_days": 7,
            "min_live_hours": 48,
            "specs": [{"id": sid, "version": SPEC_BY_ID[sid].version,
                       "key_version": SPEC_BY_ID[sid].key_version} for sid in spec_ids],
            "decay": {"rare_half_life_days": 14, "first_seen": "none"},
            "budget": budget or {"queries": 200, "records": 5_000_000, "seconds": 1800},
            "store_cut_digest": "empty",
        },
    }


def _repo(*, spec_ids=(SPEC.id,), configured=True, budget=None, targets=("host-index",)):
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt(
        "h1", _manifest(
            spec_ids=spec_ids, configured=configured, budget=budget, targets=targets,
        ), "digest", "test",
    )
    for target in targets:
        for sid in spec_ids:
            repo.set_rule_cell("h1", sid, SPEC_BY_ID[sid].version, target, WINDOW.key(),
                               "evaluated_complete", 0, 1, {})
    return repo


def _event(index: int, path: str) -> TypedEvent:
    return TypedEvent(
        id=f"event-{index:03d}", family="process_exec", ts=START + timedelta(minutes=index % 50),
        host="web01", outcome=Outcome.success,
        fields={
            "process.executable": fv(path, "fixture:process.executable"),
            "process.exec_file.path": fv(path, "fixture:process.exec_file.path"),
            "process.user": fv("svc", "fixture:process.user"),
        },
        raw=[RawRef(target="host-index", native_id=f"raw-{index:03d}")], normalizer="fixture@1",
    )


def _observation(event: TypedEvent, *, key_id: str, key_digest: str, path: str) -> dict:
    return {
        "hunt_id": "h1", "spec_id": SPEC.id, "spec_version": SPEC.version,
        "scope_kind": "host", "scope": "host:web01", "key_id": key_id,
        "key_digest": key_digest, "key": {"executable": path, "exec_file_path": path},
        "window_count": 1, "first_ts": event.ts, "last_ts": event.ts,
        "first_event_id": event.id, "history_count": None, "history_decayed": None,
        "peer_scopes_with_key": None, "peer_scopes": None, "threshold": None,
        "mean": None, "sigma": None, "n_hours": None, "verdict": "unresolved",
        "reason": "baseline judgement pending", "candidate_id": None,
    }


def _resolved_history(repo: Repo, *, known_key_id="known-id", known_digest="known-digest"):
    begin = START - timedelta(hours=48)
    repo.save_baseline_segment({
        "id": "history", "site": "site", "target": "host-index", "spec_id": SPEC.id,
        "spec_version": SPEC.version, "key_version": SPEC.key_version, "normalizer": "fixture@1",
        "start": begin, "end": START, "bucket": "day", "origin": "lookback",
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "excluded_keys": [], "hunted": 0, "events_total": 48, "status": "active", "created_at": START,
    }, [{
        "segment_id": "history", "scope_kind": "host", "scope": "host:web01",
        "key_id": known_key_id, "key_digest": known_digest,
        "key": {"executable": "/bin/known", "exec_file_path": "/bin/known"},
        "bucket": begin + timedelta(days=day), "count": 24,
        "first_ts": begin + timedelta(days=day),
        "last_ts": begin + timedelta(days=day, hours=23),
    } for day in range(2)], [{
        "segment_id": "history", "scope_kind": "host", "scope": "host:web01",
        "hour": begin + timedelta(hours=hour), "events": 1,
    } for hour in range(48)])


def test_no_pre_window_history_is_unresolved_without_a_lead_or_complete_negative():
    repo = _repo()
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="new-id", key_digest="new-digest",
                                                  path="/bin/new"))

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    row = next(repo.baseline_observations("h1"))
    assert summary["finished"] and summary["status"] == "partial"
    assert row["verdict"] == "unresolved" and "no pre-window data" in row["reason"]
    assert repo.candidates("h1") == []
    cells = [cell for cell in repo.rule_cells("h1") if cell["rule_id"] == SPEC.id]
    assert all(cell["state"] != "no_match_complete" for cell in cells)
    assert any(cell["target"] == "baseline:host-index" and cell["state"] == "partial" for cell in cells)


def test_absent_history_cannot_become_a_complete_negative_when_the_window_has_no_keys():
    repo = _repo()

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == SPEC.id and cell["target"] == "*" and cell["partition"] == "window")
    assert summary["status"] == "partial"
    assert rollup["state"] == "evaluated_partial"
    assert "no pre-window data" in rollup["detail"]["reasons"]


@pytest.mark.parametrize(("state", "reason"), [
    ("failed", "shard failure"),
    ("partial", "source result cap reached"),
    ("partial", "source timeout"),
    ("partial", "normalization_errors=1"),
])
def test_history_failure_never_becomes_first_seen_or_a_complete_negative(state, reason):
    repo = _repo()
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="new-id", key_digest="new-digest",
                                                  path="/bin/new"))

    run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory(state, reason))

    assert next(repo.baseline_observations("h1"))["verdict"] == "unresolved"
    assert repo.candidates("h1") == []
    cells = [cell for cell in repo.rule_cells("h1") if cell["rule_id"] == SPEC.id]
    expected = "failed" if state == "failed" else "partial"
    assert any(cell["state"] == expected for cell in cells)
    assert all(cell["state"] != "no_match_complete" for cell in cells)


def test_exhausted_history_budget_is_explicit_and_never_becomes_first_seen():
    source = EmptyHistory()
    repo = _repo(budget={"queries": 1, "records": 5_000_000, "seconds": 1800})
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(
        event, key_id="new-id", key_digest="new-digest", path="/bin/new",
    ))

    run_baseline_stage(repo, "h1", WINDOW, source=source)

    assert source.plans == 1
    assert next(repo.baseline_observations("h1"))["verdict"] == "unresolved"
    assert repo.candidates("h1") == []
    cells = [cell for cell in repo.rule_cells("h1") if cell["rule_id"] == SPEC.id]
    assert any(cell["state"] == "omitted_budget" for cell in cells)
    assert all(cell["state"] != "no_match_complete" for cell in cells)


def test_mid_history_gap_invalidates_an_otherwise_long_enough_recent_span():
    repo = _repo()
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="new-id", key_digest="new-digest",
                                                  path="/bin/new"))

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory("partial", "normalization_errors=1"))

    row = next(item for item in repo.baseline_observations("h1") if item["key_digest"] == "new-digest")
    assert summary["snapshot_status"] == "gap_shortened"
    assert row["verdict"] == "unresolved" and "history gap" in row["reason"]
    assert repo.candidates("h1") == []
    assert all(cell["state"] != "no_match_complete" for cell in repo.rule_cells("h1"))


def test_a_gap_on_another_target_invalidates_a_scope_seen_in_resolved_history():
    class SplitHistory(EmptyHistory):
        def plan(self, target, start, end, *, query_budget):
            if target == "broken-index":
                self.plans += 1
                return HistoryPlan((), 1, "failed", ("shard failure",))
            return super().plan(target, start, end, query_budget=query_budget)

    repo = _repo(
        targets=("host-index", "broken-index"),
        budget={"queries": 500, "records": 5_000_000, "seconds": 1800},
    )
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(
        event, key_id="new-id", key_digest="new-digest", path="/bin/new",
    ))

    run_baseline_stage(repo, "h1", WINDOW, source=SplitHistory())

    row = next(repo.baseline_observations("h1"))
    assert row["verdict"] == "unresolved" and "history gap" in row["reason"]
    assert repo.candidates("h1") == []


def test_resolved_history_marks_known_common_and_groups_all_new_keys_in_one_capped_lead():
    repo = _repo()
    _resolved_history(repo)
    rows = []
    events = []
    known = _event(0, "/bin/known")
    events.append(known)
    rows.append(_observation(known, key_id="known-id", key_digest="known-digest", path="/bin/known"))
    for index in range(1, BASELINE_CITATION_CAP + 3):
        event = _event(index, f"/opt/new-{index:02d}")
        events.append(event)
        rows.append(_observation(event, key_id=f"new-id-{index:02d}", key_digest=f"new-{index:02d}",
                                 path=f"/opt/new-{index:02d}"))
    repo.save_evidence("h1", events, {event.raw[0].key: {"message": event.id} for event in events}, None)
    repo.upsert_baseline_observations(rows)

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    observations = list(repo.baseline_observations("h1"))
    known_row = next(row for row in observations if row["key_digest"] == "known-digest")
    new_rows = [row for row in observations if row["key_digest"].startswith("new-")]
    assert known_row["verdict"] == "common" and known_row["history_count"] == 48
    assert {row["verdict"] for row in new_rows} == {"first_seen"}
    candidates = repo.candidates("h1")
    assert len(candidates) == 1 and candidates[0]["lane"] == "lead"
    assert len(candidates[0]["event_ids"]) == BASELINE_CITATION_CAP
    assert all(row["candidate_id"] == candidates[0]["id"] for row in new_rows)
    claim = candidates[0]["claim"]
    assert "absent from baseline" in claim and "never seen" not in claim
    assert "absence from a baseline is a deviation, not evidence of malicious activity" in claim
    assert f"{len(new_rows)} keys" in claim and summary["snapshot_digest"] in claim
    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == SPEC.id and cell["target"] == "*" and cell["partition"] == "window")
    assert rollup["state"] == "matched" and rollup["matched"] == 1


def test_unconfigured_external_destination_is_unresolved_even_with_resolved_history():
    ext = SPEC_BY_ID["bl.ext_dest"]
    repo = _repo(spec_ids=(ext.id,), configured=False)
    event = TypedEvent(
        id="flow", family="net_flow", ts=START, host="sensor", outcome=Outcome.unknown,
        fields={"source.ip": fv("10.0.0.5", "fixture:source.ip"),
                "destination.ip": fv("8.8.8.8", "fixture:destination.ip")},
        raw=[RawRef(target="host-index", native_id="flow")], normalizer="fixture@1",
    )
    row = _observation(event, key_id="dest-id", key_digest="dest-digest", path="8.8.8.8")
    row.update(spec_id=ext.id, spec_version=ext.version, scope_kind="internal_ip", scope="internal_ip:10.0.0.5",
               key={"kind": "dest_ip", "dest_ip": "8.8.8.8"})
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "flow"}}, None)
    repo.upsert_baseline_observation(row)

    run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    stored = next(repo.baseline_observations("h1"))
    assert stored["verdict"] == "unresolved"
    assert "internal networks not configured" in stored["reason"]
    assert repo.candidates("h1") == []


def test_configured_external_destination_is_evaluated_against_resolved_history():
    ext = SPEC_BY_ID["bl.ext_dest"]
    repo = _repo(spec_ids=(ext.id,), configured=True)
    begin = START - timedelta(hours=48)
    repo.save_baseline_segment({
        "id": "ext-history", "site": "site", "target": "host-index", "spec_id": ext.id,
        "spec_version": ext.version, "key_version": ext.key_version, "normalizer": "fixture@1",
        "start": begin, "end": START, "bucket": "day", "origin": "lookback",
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "excluded_keys": [], "hunted": 0, "events_total": 48, "status": "active", "created_at": START,
    }, [{
        "segment_id": "ext-history", "scope_kind": "internal_ip", "scope": "internal_ip:10.0.0.5",
        "key_id": "known-dest", "key_digest": "known-dest-digest",
        "key": {"kind": "dest_ip", "dest_ip": "1.1.1.1"},
        "bucket": begin + timedelta(days=day), "count": 24,
        "first_ts": begin + timedelta(days=day), "last_ts": begin + timedelta(days=day, hours=23),
    } for day in range(2)], [{
        "segment_id": "ext-history", "scope_kind": "internal_ip", "scope": "internal_ip:10.0.0.5",
        "hour": begin + timedelta(hours=hour), "events": 1,
    } for hour in range(48)])
    event = TypedEvent(
        id="flow-new", family="net_flow", ts=START, host="sensor", outcome=Outcome.unknown,
        fields={"source.ip": fv("10.0.0.5", "fixture:source.ip"),
                "destination.ip": fv("8.8.8.8", "fixture:destination.ip")},
        raw=[RawRef(target="host-index", native_id="flow-new")], normalizer="fixture@1",
    )
    row = _observation(event, key_id="new-dest", key_digest="new-dest-digest", path="8.8.8.8")
    row.update(spec_id=ext.id, spec_version=ext.version, scope_kind="internal_ip",
               scope="internal_ip:10.0.0.5", key={"kind": "dest_ip", "dest_ip": "8.8.8.8"})
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "flow"}}, None)
    repo.upsert_baseline_observation(row)

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    assert next(repo.baseline_observations("h1"))["verdict"] == "first_seen"
    assert summary["status"] == "complete"
    assert len(repo.candidates("h1")) == 1


def test_stage_resume_reuses_the_frozen_snapshot_and_is_idempotent():
    repo = _repo()
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="new-id", key_digest="new-digest",
                                                  path="/bin/new"))
    first_source = EmptyHistory()
    first = run_baseline_stage(repo, "h1", WINDOW, source=first_source)
    first_candidates = repo.candidates("h1")
    later_source = EmptyHistory("failed", "must not be called")

    resumed = run_baseline_stage(repo, "h1", WINDOW, source=later_source)

    assert resumed["snapshot_digest"] == first["snapshot_digest"]
    assert later_source.plans == 0
    assert repo.candidates("h1") == first_candidates


def test_twin_stage_runs_are_canonical_identical():
    def run_once():
        repo = _repo()
        _resolved_history(repo)
        event = _event(1, "/bin/new")
        repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
        repo.upsert_baseline_observation(_observation(
            event, key_id="new-id", key_digest="new-digest", path="/bin/new",
        ))
        summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())
        candidates = [{key: value for key, value in row.items() if key != "created_at"}
                      for row in repo.candidates("h1")]
        return summary, list(repo.baseline_observations("h1")), candidates, repo.rule_cells("h1")

    assert run_once() == run_once()


def test_run_orders_baseline_after_packets_before_expansion_and_resume_retries_a_crash(monkeypatch, tmp_path):
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    manifest = _manifest()
    manifest.update(
        normalizer=NORMALIZER_VERSION, packet_normalizer=PACKET_NORMALIZER,
        agent_mode="off", ai_agent={"requested": False}, source_profiles={},
        expansion={"enabled": True},
        internal_networks=SiteNetworks.from_lists(["10.0.0.0/8"]).record(),
    )
    repo.create_hunt("h1", manifest, "digest", "test")
    order = []

    class FakeSweep:
        def __init__(self, *_args, **_kwargs):
            self.partial_reasons, self.stats = [], {}

        def run_target(self, _target):
            return None

        def finalize(self):
            return None

        def close_stage(self):
            return None

    calls = 0

    def packet(*_args, **_kwargs):
        order.append("packet")
        summary = {"status": "complete", "finished": True}
        repo.audit("system", "hunt.packet_summary", "h1", summary)
        return summary

    def baseline(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        order.append("baseline")
        if calls == 1:
            raise RuntimeError("history source offline")
        return {"status": "complete", "finished": True, "snapshot_digest": "frozen", "specs": {}}

    def expansion(*_args, **_kwargs):
        order.append("expansion")
        return {"status": "complete"}

    monkeypatch.setattr(hunt_run, "open_repo", lambda _settings: repo)
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(hunt_run, "Sweep", FakeSweep)
    monkeypatch.setattr(hunt_run, "_site_network_check", lambda *_args, **_kwargs: {
        "definition": "configured", "warning": None,
    })
    monkeypatch.setattr(hunt_run, "_packet_stage", packet)
    monkeypatch.setattr(hunt_run, "run_baseline_stage", baseline)
    monkeypatch.setattr(hunt_run, "_run_expansion_safely", expansion)
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *_args, **_kwargs: {"status": "disabled"})
    settings = Settings(home=tmp_path, internal_networks=["10.0.0.0/8"])

    first = hunt_run.run_hunt(settings, "h1")
    resumed = hunt_run.resume_hunt(settings, "h1")

    assert order[:3] == ["packet", "baseline", "expansion"]
    assert order[3:] == ["baseline", "expansion"]
    assert first["execution_state"] == "partial" and first["baseline"]["finished"] is False
    assert resumed["baseline"] == {
        "status": "complete", "finished": True, "snapshot_digest": "frozen", "specs": {},
    }
    assert repo.latest_audit("h1", "hunt.baseline_summary")["detail"]["finished"] is True


def test_hunt_manifest_records_the_frozen_baseline_plan_and_network_definition():
    settings = Settings(site="mission-a", internal_networks=["10.0.0.0/8"])

    manifest = build_manifest(settings, WINDOW, {}, "broad", ["b", "a"], {})
    baseline = manifest["baseline"]

    assert baseline["plan_version"] == "baseline-plan@1" and baseline["site"] == "mission-a"
    assert baseline["history_days"] == 7 and baseline["min_live_hours"] == 48
    assert baseline["budget"] == {"queries": 200, "records": 5_000_000, "seconds": 1800}
    assert {item["id"] for item in baseline["specs"]} == {
        "bl.ssh_tuple", "bl.exec_path", "bl.exec_pair", "bl.cmd_shape", "bl.ext_dest",
    }
    assert "bl.svc_exec_rate" not in {item["id"] for item in baseline["specs"]}
    assert baseline["internal_networks"]["source"] == "configured"
    assert baseline["store_cut_digest"]
    default_a = build_manifest(Settings(), WINDOW, {}, "broad", ["b", "a"], {})["baseline"]["site"]
    default_b = build_manifest(Settings(), WINDOW, {}, "broad", ["a", "b"], {})["baseline"]["site"]
    assert default_a == default_b and default_a.startswith("targets-sha256:")
