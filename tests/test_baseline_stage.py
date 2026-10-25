"""Post-packet baseline judgement, publication, coverage, and resume semantics."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.playbook import CommandShapeBaseline, ExecPathBaseline, SshTupleBaseline
from romulus.baseline.protocol import HistoryFetch, HistoryPartition, HistoryPlan
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import run as hunt_run
from romulus.hunt.baseline_stage import BASELINE_CITATION_CAP, SnapshotView, run_baseline_stage
from romulus.hunt.manifest import build_manifest
from romulus.hunt.packets import PACKET_NORMALIZER
from romulus.hunt.sweep import BOOT_PLACEMENT_PARTITION
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
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


class _ClaimRepo:
    def get_hunt(self, _hunt_id):
        return {"manifest": {}}

    def baseline_snapshot_exclusions(self, _hunt_id, _spec_id):
        return {"segments": 0, "hunted_segments": 0, "excluded_keys": 0}


def _claim(playbook, rows):
    view = SnapshotView(
        _ClaimRepo(), "h1", WINDOW,
        {"digest": "snapshot", "plan": {}}, min_live_hours=48, networks_configured=True,
    )
    facts = {
        "effective_start": (START - timedelta(hours=48)).isoformat(),
        "effective_hours": 48, "live_hours": 48, "history_events": 96, "coverage": [],
    }
    return view._claim(playbook, "site", rows, facts, len(rows))


def test_command_shape_claim_states_the_shape_and_its_masking_policy():
    row = {
        "key": {"executable": "/usr/bin/tool", "argv_shape": ["tool", "<ip>", "<b64:16-31>"]},
        "window_count": 1, "peer_scopes": 1, "peer_scopes_with_key": 0,
    }

    claim = _claim(CommandShapeBaseline(), [row])

    assert '"argv_shape":["tool","<ip>","<b64:16-31>"]' in claim
    assert "argv masking replaces" in claim
    assert all(name in claim for name in ("IP literals", "numbers", "UUIDs", "hexadecimal", "Base64"))
    assert "random tmp/temp basenames" in claim and "preserving their directories" in claim
    assert "chmod permission modes and non-temp path text remain literal" in claim


@pytest.mark.parametrize(("peers", "present"), [(4, False), (5, True)])
def test_ssh_claim_includes_peer_prevalence_only_with_at_least_five_peers(peers, present):
    row = {
        "key": {"kind": "source_ip", "source_ip": "192.0.2.19"},
        "window_count": 1, "peer_scopes": peers, "peer_scopes_with_key": 1,
    }

    claim = _claim(SshTupleBaseline(), [row])

    assert ("peer prevalence 1/" in claim) is present


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


def test_target_without_required_fields_does_not_gate_the_specs_history():
    class SplitHistory(EmptyHistory):
        def plan(self, target, start, end, *, query_budget):
            if target == "network-index":
                raise AssertionError("inapplicable target must not be queried for exec history")
            return super().plan(target, start, end, query_budget=query_budget)

    repo = _repo(targets=("host-index", "network-index"))
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(
        event, key_id="new-id", key_digest="new-digest", path="/bin/new",
    ))
    contracts = {
        "host-index": contract_from_types("host-index", {
            "process.executable": "keyword", "process.exec_file.path": "keyword",
            "process.user": "keyword",
        }, role="host"),
        "network-index": contract_from_types("network-index", {
            "source.ip": "ip", "destination.ip": "ip",
        }, role="network", os_family="unknown"),
    }

    run_baseline_stage(repo, "h1", WINDOW, source=SplitHistory(), contracts=contracts)

    assert next(repo.baseline_observations("h1"))["verdict"] == "first_seen"
    assert len(repo.candidates("h1")) == 1
    history_cell = next(cell for cell in repo.rule_cells("h1")
                        if cell["target"] == "baseline:network-index")
    assert history_cell["state"] == "not_applicable_no_events"


def test_a_scope_with_no_history_events_is_named_as_silent():
    repo = _repo()
    _resolved_history(repo)
    event = _event(1, "/bin/new").model_copy(update={"host": "newhost"})
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    row = _observation(event, key_id="new-id", key_digest="new-digest", path="/bin/new")
    row["scope"] = "host:newhost"
    repo.upsert_baseline_observation(row)

    source = EmptyHistory()
    run_baseline_stage(repo, "h1", WINDOW, source=source)

    stored = next(repo.baseline_observations("h1"))
    assert stored["verdict"] == "unresolved"
    assert stored["reason"] == "scope is silent in history"
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
    assert '"executable":"/opt/new-20"' in claim
    assert '"executable":"/opt/new-21"' not in claim
    assert "and 2 more keys (in the observation table)" in claim
    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == SPEC.id and cell["target"] == "*" and cell["partition"] == "window")
    assert rollup["state"] == "matched" and rollup["matched"] == 1


def test_boot_placement_partial_gates_rollup_but_not_a_present_keys_first_seen_verdict():
    repo = _repo()
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(
        event, key_id="new-id", key_digest="new-digest", path="/bin/new",
    ))
    repo.set_rule_cell(
        "h1", SPEC.id, SPEC.version, "*", BOOT_PLACEMENT_PARTITION,
        "evaluated_partial", 0, 0, {"reasons": ["boot placement conflict"]},
    )

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    assert next(repo.baseline_observations("h1"))["verdict"] == "first_seen"
    assert len(repo.candidates("h1")) == 1
    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == SPEC.id and cell["target"] == "*" and cell["partition"] == "window")
    assert rollup["state"] == "match_on_partial"
    assert summary["specs"][SPEC.id]["window_failure"] == "window coverage is partial in 1 cell(s)"


def test_baseline_uses_the_specs_version_even_when_the_playbook_class_disagrees(monkeypatch):
    repo = _repo()
    _resolved_history(repo)
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "new"}}, None)
    repo.upsert_baseline_observation(_observation(
        event, key_id="new-id", key_digest="new-digest", path="/bin/new",
    ))
    monkeypatch.setattr(ExecPathBaseline, "version", "legacy-mismatch")

    run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    candidate = repo.candidates("h1")[0]
    assert candidate["rule_version"] == SPEC.version
    assert all(cell["rule_version"] == SPEC.version for cell in repo.rule_cells("h1")
               if cell["rule_id"] == SPEC.id)


def test_judge_fetches_and_persists_only_published_first_event_citations():
    repo = _repo()
    _resolved_history(repo)
    rows, events = [], []
    for index in range(BASELINE_CITATION_CAP + 3):
        event = _event(index + 1, f"/opt/new-{index:02d}")
        event.fields["aaa.irrelevant"] = fv("noise", "fixture:irrelevant")
        events.append(event)
        row = _observation(
            event, key_id=f"new-id-{index:02d}", key_digest=f"new-{index:02d}",
            path=f"/opt/new-{index:02d}",
        )
        row["first_event_refs"] = [
            {"target": event.raw[0].target, "native_id": event.raw[0].native_id},
        ]
        rows.append(row)
    repo.upsert_baseline_observations(rows)

    class CitationSource(EmptyHistory):
        def __init__(self):
            super().__init__()
            self.requested = []

        def fetch_refs(self, refs):
            self.requested.extend(refs)
            wanted = {(ref["target"], ref["native_id"]) for ref in refs}
            selected = [event for event in events
                        if (event.raw[0].target, event.raw[0].native_id) in wanted]
            raw = {event.raw[0].key: {"message": event.id} for event in selected}
            return selected, raw, []

    source = CitationSource()
    run_baseline_stage(repo, "h1", WINDOW, source=source)

    candidate = repo.candidates("h1")[0]
    assert len(source.requested) == BASELINE_CITATION_CAP
    assert len(candidate["event_ids"]) == BASELINE_CITATION_CAP
    assert len(repo.events_by_ids([event.id for event in events])) == BASELINE_CITATION_CAP
    assert {item["field"] for item in candidate["predicate_fields"]} == {
        "process.executable", "process.exec_file.path", "process.user",
    }


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

    source = EmptyHistory()
    run_baseline_stage(repo, "h1", WINDOW, source=source)

    stored = next(repo.baseline_observations("h1"))
    assert stored["verdict"] == "unresolved"
    assert "internal networks not configured" in stored["reason"]
    assert repo.candidates("h1") == []
    assert source.plans == 0
    assert repo.baseline_segments(spec_id=ext.id) == []


def test_configured_external_destination_is_evaluated_against_resolved_history():
    ext = SPEC_BY_ID["bl.ext_dest"]
    repo = _repo(spec_ids=(ext.id,), configured=True)
    begin = START - timedelta(hours=48)
    repo.save_baseline_segment({
        "id": "ext-history", "site": "site", "target": "host-index", "spec_id": ext.id,
        "spec_version": ext.version, "key_version": ext.key_version, "normalizer": "fixture@1",
        "start": begin, "end": START, "bucket": "day", "origin": "lookback",
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "network_digest": "fixture",
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
    assert {key: resumed["baseline"][key] for key in ("status", "finished", "snapshot_digest", "specs")} == {
        "status": "complete", "finished": True, "snapshot_digest": "frozen", "specs": {},
    }
    assert resumed["baseline"]["segment_writer"]["specs"]["bl.exec_path"]["reason"] == (
        "host-index: no window cells"
    )
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
        "bl.svc_exec_rate",
    }
    assert baseline["thresholds"]["rate"] == {"min_count": 5.0, "k": 3.0, "z": 4.0}
    assert baseline["internal_networks"]["source"] == "configured"
    assert baseline["store_cut_digest"]
    default_a = build_manifest(Settings(), WINDOW, {}, "broad", ["b", "a"], {})["baseline"]["site"]
    default_b = build_manifest(Settings(), WINDOW, {}, "broad", ["a", "b"], {})["baseline"]["site"]
    assert default_a == default_b and default_a.startswith("targets-sha256:")


def _lab_profile(repo: Repo, target: str, datasets: dict[str, int]) -> None:
    repo.save_profile("h1", {
        "id": f"profile-{target}", "target": target, "kind": "es_index", "role": "host", "os_family": "linux",
        "datasets": datasets, "notes": [],
    })


def _lab_contract(target: str):
    from tests.throughput_fixture import HOST_TYPES

    return contract_from_types(target, HOST_TYPES)


class TimedHistory(EmptyHistory):
    """Complete history whose hours hold the given events, per target."""

    def __init__(self, events_by_target: dict[str, list[TypedEvent]]):
        super().__init__()
        self.events_by_target = events_by_target

    def _events(self, target, start, end):
        return [event for event in self.events_by_target.get(target, []) if start <= event.ts < end]

    def plan(self, target, start, end, *, query_budget):
        self.plans += 1
        return HistoryPlan((HistoryPartition(target, start, end, len(self._events(target, start, end)),
                                             start.isoformat()),), 1, "complete", ())

    def fetch(self, partition, *, record_budget=None, query_budget=None, deadline=None):
        events = tuple(self._events(partition.target, partition.start, partition.end))
        return HistoryFetch(events, "complete", (), len(events), 1)


def _exec_event(event_id: str, ts: datetime, *, pid: int, ppid: int, executable: str,
                target: str = "host-index") -> TypedEvent:
    values = {"process.pid": pid, "process.ppid": ppid, "process.executable": executable,
              "process.exec_file.path": executable, "process.user": "svc", "host.boot.id": "boot-1"}
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host="web01", outcome=Outcome.success,
        fields={name: fv(value, f"fixture:{name}") for name, value in values.items()},
        raw=[RawRef(target=target, native_id=f"raw-{event_id}")], normalizer="fixture@1",
    )


def test_an_audit_target_whose_exec_fields_are_unmapped_reads_history_and_resolves_a_pre_window_parent(
        monkeypatch, tmp_path):
    from romulus.baseline.playbook import ExecPairBaseline
    from romulus.hunt import sweep as sweep_module
    from tests.test_baseline_sweep import FakeClient, _install_partition

    pair = SPEC_BY_ID["bl.exec_pair"]
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", _manifest(
        spec_ids=(pair.id,), budget={"queries": 1000, "records": 5_000_000, "seconds": 1800},
    ), "digest", "test")
    _lab_profile(repo, "host-index", {"linux.audit": 10, "systemd.journal": 10})
    contracts = {"host-index": _lab_contract("host-index")}
    child = _exec_event("child", START + timedelta(minutes=5), pid=20, ppid=10, executable="/bin/curl")
    _install_partition(monkeypatch, [child], window=WINDOW)
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", WINDOW, contracts, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]
    sweep.run_target("host-index")
    sweep.close_stage()
    parent = _exec_event("parent", START - timedelta(minutes=30), pid=10, ppid=1, executable="/usr/sbin/sshd")
    source = TimedHistory({"host-index": [parent]})

    run_baseline_stage(repo, "h1", WINDOW, source=source, contracts=contracts)

    assert source.plans == 7 * 24
    observation = next(repo.baseline_observations("h1"))
    assert observation["key"] == {"child_executable": "/bin/curl", "parent_executable": "/usr/sbin/sshd"}
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == WINDOW.key())
    assert cell["state"] == "evaluated_complete"
    history = next(row for row in repo.rule_cells("h1") if row["target"] == "baseline:host-index")
    assert history["detail"]["coverage"]["status"] != "not_applicable"


def test_an_audit_target_reads_its_history_and_states_absence_not_silence():
    repo = _repo()
    _lab_profile(repo, "host-index", {"linux.audit": 10})
    event = _event(1, "/bin/new")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"m": 1}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="n", key_digest="n", path="/bin/new"))
    source = EmptyHistory()

    summary = run_baseline_stage(repo, "h1", WINDOW, source=source,
                                 contracts={"host-index": _lab_contract("host-index")})

    row = next(repo.baseline_observations("h1"))
    assert source.plans == 7 * 24
    assert row["verdict"] == "unresolved" and row["reason"] == "no pre-window data"
    history = next(cell for cell in repo.rule_cells("h1") if cell["target"] == "baseline:host-index")
    assert history["state"] != "not_applicable_no_events"
    assert history["detail"]["coverage"]["status"] == "absent"
    assert summary["specs"][SPEC.id]["history_failure"] == "no pre-window data"


def test_a_host_split_between_a_mapped_and_an_audit_target_never_claims_a_false_first_seen():
    repo = _repo(targets=("mapped-index", "audit-index"),
                 budget={"queries": 1000, "records": 5_000_000, "seconds": 1800})
    _lab_profile(repo, "mapped-index", {"linux.audit": 10})
    _lab_profile(repo, "audit-index", {"linux.audit": 10})
    hours = [START - timedelta(hours=hour) for hour in range(1, 49)]
    mapped = [_exec_event(f"m{index}", hour, pid=100 + index, ppid=1, executable="/bin/other",
                          target="mapped-index") for index, hour in enumerate(hours)]
    audited = [_exec_event(f"a{index}", hour + timedelta(minutes=1), pid=500 + index, ppid=1,
                           executable="/bin/known", target="audit-index") for index, hour in enumerate(hours)]
    window_event = _event(1, "/bin/known")
    repo.save_evidence("h1", [window_event], {window_event.raw[0].key: {"m": 1}}, None)
    key = next(item for item in SPEC.keys(window_event, KeyContext()) if item.scope_kind == "host")
    row = _observation(window_event, key_id=key.key_id, key_digest=key.key_digest, path="/bin/known")
    repo.upsert_baseline_observation({**row, "scope": key.scope, "key": key.key})
    contracts = {
        "mapped-index": contract_from_types("mapped-index", {
            "@timestamp": "date", "host.name": "keyword", "process.executable": "keyword",
            "process.exec_file.path": "keyword", "process.user": "keyword",
        }),
        "audit-index": _lab_contract("audit-index"),
    }

    run_baseline_stage(repo, "h1", WINDOW, source=TimedHistory({"mapped-index": mapped, "audit-index": audited}),
                       contracts=contracts)

    stored = next(repo.baseline_observations("h1"))
    assert stored["verdict"] == "common" and stored["history_count"] == 48
    assert repo.candidates("h1") == []


def test_an_unresolvable_history_child_leaves_the_baseline_unresolved_without_failing_the_stage():
    child = _exec_event("hist-child", START - timedelta(minutes=55), pid=200, ppid=77, executable="/bin/ls")
    repo = _repo(spec_ids=("bl.exec_pair",), budget={"queries": 1000, "records": 5_000_000, "seconds": 1800})

    summary = run_baseline_stage(repo, "h1", WINDOW, source=TimedHistory({"host-index": [child]}))

    gaps = next(iter(repo.baseline_snapshot("h1")["coverage"].values()))["gaps"]
    assert [(gap["state"], gap["start"]) for gap in gaps] == [
        ("unresolved", (START - timedelta(hours=1)).isoformat()),
    ]
    assert "parent exec before history" in gaps[0]["reason"]
    assert summary["status"] == "partial" and summary["stage_failed"] is False
    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == "bl.exec_pair" and cell["target"] == "*")
    assert rollup["state"] == "evaluated_partial"
    history = next(cell for cell in repo.rule_cells("h1") if cell["target"] == "baseline:host-index")
    assert history["state"] == "partial"


@pytest.mark.parametrize(("state", "reason"), [("failed", "shard failure"), ("partial", "source timeout")])
def test_a_history_source_failure_fails_the_baseline_stage(state, reason):
    repo = _repo()

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory(state, reason))

    assert summary["stage_failed"] is True


def test_a_history_child_resolves_to_a_parent_in_an_older_history_hour():
    parent = _exec_event("hist-parent", START - timedelta(hours=5), pid=77, ppid=1, executable="/usr/sbin/sshd")
    child = _exec_event("hist-child", START - timedelta(minutes=55), pid=200, ppid=77, executable="/bin/ls")
    repo = _repo(spec_ids=("bl.exec_pair",), budget={"queries": 1000, "records": 5_000_000, "seconds": 1800})

    run_baseline_stage(repo, "h1", WINDOW, source=TimedHistory({"host-index": [parent, child]}))

    coverage = next(iter(repo.baseline_snapshot("h1")["coverage"].values()))
    assert coverage["gaps"] == []
    segment = next(row for row in repo.baseline_segments(statuses=["active"])
                   if row["start"] == START - timedelta(hours=1))
    assert [row["key"] for row in repo.baseline_counts(segment["id"])] == [
        {"child_executable": "/bin/ls", "parent_executable": "/usr/sbin/sshd"},
    ]
    parent_segment = next(row for row in repo.baseline_segments(statuses=["active"])
                          if row["start"] == START - timedelta(hours=5))
    assert [row["key"] for row in repo.baseline_counts(parent_segment["id"])] == [
        {"child_executable": "/usr/sbin/sshd", "parent_executable": "init"},
    ]


def test_a_lookback_budget_running_out_leaves_history_short_without_failing_the_stage():
    """A dense hour that needs more planning queries than remain is short history (omitted_budget), not a baseline
    stage failure: the hunt is not made partial by its own lookback budget."""
    from romulus.baseline.protocol import HistoryPlan

    class EdgeBudget(EmptyHistory):
        def plan(self, target, start, end, *, query_budget):
            self.plans += 1
            if query_budget < 2:
                return HistoryPlan((), query_budget, "omitted_budget", ("planning query budget exhausted",))
            return super().plan(target, start, end, query_budget=query_budget)

    repo = _repo(budget={"queries": 5, "records": 5_000_000, "seconds": 1800})
    summary = run_baseline_stage(repo, "h1", WINDOW, source=EdgeBudget())
    gaps = [gap for coverage in repo.baseline_snapshot("h1")["coverage"].values() for gap in coverage["gaps"]]
    assert summary["stage_failed"] is False
    assert ("omitted_budget", "planning query budget exhausted") in {(g["state"], g["reason"]) for g in gaps}


def test_a_segment_straddling_history_start_contributes_only_its_in_span_rows():
    window = Window(start=START + timedelta(hours=12), end=START + timedelta(hours=13))
    history_start = window.start - timedelta(days=7)
    begin = history_start - timedelta(days=1)
    old_seen = history_start - timedelta(hours=4)    # the same UTC day as history_start, before it
    repo = _repo()
    repo.save_baseline_segment({
        "id": "straddle", "site": "site", "target": "host-index", "spec_id": SPEC.id,
        "spec_version": SPEC.version, "key_version": SPEC.key_version, "normalizer": "fixture@1",
        "start": begin, "end": window.start, "bucket": "day", "origin": "hunt",
        "source_hunt_id": "earlier", "built_by_hunt_id": "earlier", "exclusion_digest": "none",
        "excluded_keys": [], "hunted": 1, "events_total": 8 * 24, "first_event_hour": begin,
        "status": "active", "created_at": START,
    }, [{
        "segment_id": "straddle", "scope_kind": "host", "scope": "host:web01", "key_id": "old-id",
        "key_digest": "old-digest", "key": {"executable": "/bin/old", "exec_file_path": "/bin/old"},
        "bucket": old_seen.replace(hour=0), "count": 1, "first_ts": old_seen, "last_ts": old_seen,
    }, {
        "segment_id": "straddle", "scope_kind": "host", "scope": "host:web01", "key_id": "known-id",
        "key_digest": "known-digest", "key": {"executable": "/bin/known", "exec_file_path": "/bin/known"},
        "bucket": window.start.replace(hour=0), "count": 1,
        "first_ts": window.start - timedelta(hours=1), "last_ts": window.start - timedelta(hours=1),
    }], [{
        "segment_id": "straddle", "scope_kind": "host", "scope": "host:web01",
        "hour": begin + timedelta(hours=hour), "events": 1,
    } for hour in range(8 * 24)], [{"hour": begin + timedelta(hours=hour), "events": 1} for hour in range(8 * 24)])
    event = _event(1, "/bin/old")
    repo.save_evidence("h1", [event], {event.raw[0].key: {"message": "old"}}, None)
    repo.upsert_baseline_observation(_observation(event, key_id="old-id", key_digest="old-digest",
                                                  path="/bin/old"))

    run_baseline_stage(repo, "h1", window, source=EmptyHistory())

    row = next(repo.baseline_observations("h1"))
    assert row["verdict"] == "first_seen" and row["history_count"] == 0
    assert row["n_hours"] == 7 * 24
    assert "history count 0" in repo.candidates("h1")[0]["claim"]
    assert "at most 0" not in repo.candidates("h1")[0]["claim"]


def test_history_stopped_on_budget_is_never_called_absent():
    """'no pre-window data' is said only when every hour was read and empty; hours the lookback budget never reached
    are named as not read."""
    from romulus.hunt.baseline_stage import _coverage_failure
    read_all = [{"status": "absent", "gaps": []}]
    assert _coverage_failure(read_all, 24) == "no pre-window data"
    stopped = [{"status": "absent", "gaps": [
        {"start": "2024-11-11T10:00:00+00:00", "end": "2024-11-15T16:00:00+00:00", "state": "omitted_budget",
         "reason": "lookback query or wall-clock budget exhausted"}]},
        {"status": "absent", "gaps": [
            {"start": "2024-11-11T10:00:00+00:00", "end": "2024-11-15T15:00:00+00:00", "state": "omitted_budget",
             "reason": "lookback query or wall-clock budget exhausted"}]}]
    assert _coverage_failure(stopped, 24) == (
        "no pre-window data in the complete hours from 2024-11-15T16:00:00+00:00 to the window start; history not "
        "read before 2024-11-15T15:00:00+00:00: lookback budget exhausted")
    failed = [{"status": "absent", "gaps": [{"start": "2024-11-15T10:00:00+00:00", "end": "2024-11-15T11:00:00+00:00",
                                             "state": "failed", "reason": "query failed"}]}]
    assert _coverage_failure(failed, 24) == (
        "no pre-window data in the complete hours from 2024-11-15T11:00:00+00:00 to the window start; history gap "
        "before them: query failed")


def test_absent_history_names_every_gap_reason_not_only_the_budget():
    """The S9 repro: the run before the window is complete and empty back to an unresolved hour (an exec without
    process.exec_file.path), older hours hold records, and older still the budget stopped the read. The reason names
    the unresolved hour's cause and never implies that no hour read held records."""
    from romulus.hunt.baseline_stage import _coverage_failure
    coverage = [{"status": "absent", "effective_hours": 0, "gaps": [
        {"start": "2024-11-05T19:00:00+00:00", "end": "2024-11-10T17:00:00+00:00", "state": "omitted_budget",
         "reason": "lookback query or wall-clock budget exhausted"},
        {"start": "2024-11-12T16:00:00+00:00", "end": "2024-11-12T17:00:00+00:00", "state": "unresolved",
         "reason": "bl.exec_path: event-9: process.exec_file.path is absent"}]}]

    reason = _coverage_failure(coverage, 48)

    assert reason == (
        "no pre-window data in the complete hours from 2024-11-12T17:00:00+00:00 to the window start; history gap "
        "before them: bl.exec_path: event-9: process.exec_file.path is absent; history not read before "
        "2024-11-10T17:00:00+00:00: lookback budget exhausted")
    assert "in the hours read" not in reason


def test_a_spec_whose_coverage_fixes_every_verdict_probes_no_key_and_streams_its_rows(monkeypatch):
    """No pre-window data: every scope is unresolved whatever its keys, so no per-key or per-scope probe runs. The
    reason stays exact, the history fields are left unassessed, and the rows are written in bounded chunks."""
    from romulus.hunt import baseline_stage

    repo = _repo()
    rows = []
    for index in range(2_500):
        event = _event(index, f"/opt/tool-{index:05d}")
        rows.append({**_observation(event, key_id=f"id-{index:05d}", key_digest=f"d-{index:05d}",
                                    path=f"/opt/tool-{index:05d}"), "scope": f"host:web{index % 7:02d}"})
    repo.upsert_baseline_observations(rows)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a probe ran for a verdict the spec's coverage already fixed")

    for name in ("baseline_key_history", "baseline_key_prevalence", "baseline_key_history_counts",
                 "baseline_key_prevalences", "baseline_scope_series", "baseline_peer_scopes"):
        monkeypatch.setattr(repo, name, forbidden)
    batches: list[int] = []
    real_upsert = repo.upsert_baseline_observations

    def upsert(items, **kwargs):
        items = list(items)
        batches.append(len(items))
        return real_upsert(items, **kwargs)

    monkeypatch.setattr(repo, "upsert_baseline_observations", upsert)

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    observed = list(repo.baseline_observations("h1"))
    assert len(observed) == 2_500 and {row["verdict"] for row in observed} == {"unresolved"}
    assert {row["reason"] for row in observed} == {summary["specs"][SPEC.id]["history_failure"]}
    assert summary["specs"][SPEC.id]["history_failure"] == "no pre-window data"
    assert all(row[name] is None for row in observed
               for name in ("history_count", "n_hours", "peer_scopes", "peer_scopes_with_key"))
    assert max(batches) <= baseline_stage._JUDGE_CHUNK and sum(batches) == 2_500
    assert summary["specs"][SPEC.id]["unresolved"] == 2_500


def test_batched_history_and_prevalence_probes_equal_the_per_key_probes():
    repo = _repo()
    _resolved_history(repo)
    span = (START - timedelta(hours=48), START)
    repo.save_baseline_snapshot({
        "hunt_id": "h1", "plan": {}, "store_cut": {}, "segment_ids": ["history"], "coverage": {},
        "status": "resolved", "digest": "snap",
    })
    key_ids = ["known-id", "absent-id"]

    history = repo.baseline_key_history_counts(key_ids, "host", "host:web01", "h1", SPEC.id, span)
    prevalence = repo.baseline_key_prevalences(key_ids, "host", "h1", SPEC.id, span)

    for key_id in key_ids:
        assert history[key_id] == sum(int(row["count"]) for row in repo.baseline_key_history(
            key_id, "host", "host:web01", "h1", SPEC.id, span))
        assert prevalence[key_id] == repo.baseline_key_prevalence(key_id, "host", "h1", SPEC.id, span)
    assert history == {"known-id": 48, "absent-id": 0} and prevalence == {"known-id": 1, "absent-id": 0}


def test_resolved_scopes_are_judged_in_bounded_chunks_with_one_batched_probe_per_chunk(monkeypatch):
    from romulus.hunt import baseline_stage

    repo = _repo()
    _resolved_history(repo)
    rows, events = [], []
    for index in range(2_300):
        event = _event(index, f"/opt/new-{index:05d}")
        events.append(event)
        rows.append(_observation(event, key_id=f"new-id-{index:05d}", key_digest=f"new-{index:05d}",
                                 path=f"/opt/new-{index:05d}"))
    cited = events[:BASELINE_CITATION_CAP]
    repo.save_evidence("h1", cited, {event.raw[0].key: {"message": event.id} for event in cited}, None)
    repo.upsert_baseline_observations(rows)
    calls: list[int] = []
    real = repo.baseline_key_history_counts

    def counted(key_ids, *args, **kwargs):
        calls.append(len(key_ids))
        return real(key_ids, *args, **kwargs)

    def per_key(*_args, **_kwargs):
        raise AssertionError("a per-key probe ran")

    monkeypatch.setattr(repo, "baseline_key_history_counts", counted)
    monkeypatch.setattr(repo, "baseline_key_history", per_key)
    monkeypatch.setattr(repo, "baseline_key_prevalence", per_key)

    run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    assert calls == [baseline_stage._JUDGE_CHUNK, baseline_stage._JUDGE_CHUNK, 300]
    observed = list(repo.baseline_observations("h1"))
    assert {row["verdict"] for row in observed} == {"first_seen"}
    candidate = repo.candidates("h1")[0]
    # every key of the scope is tied to the one lead, though the judge held only the cited ones
    assert all(row["candidate_id"] == candidate["id"] for row in observed)
    assert "2300 keys in host:web01 were absent" in candidate["claim"]
    assert "and 2280 more keys (in the observation table)" in candidate["claim"]


def test_a_contradicted_internal_network_definition_keeps_external_destinations_from_a_complete_negative():
    ext = SPEC_BY_ID["bl.ext_dest"]
    repo = _repo(spec_ids=(ext.id,), configured=True)
    begin = START - timedelta(hours=48)
    repo.save_baseline_segment({
        "id": "ext-history", "site": "site", "target": "host-index", "spec_id": ext.id,
        "spec_version": ext.version, "key_version": ext.key_version, "normalizer": "fixture@1",
        "start": begin, "end": START, "bucket": "day", "origin": "lookback",
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "network_digest": "fixture", "excluded_keys": [], "hunted": 0, "events_total": 48, "status": "active",
        "created_at": START,
    }, [], [{
        "segment_id": "ext-history", "scope_kind": "internal_ip", "scope": "internal_ip:10.0.0.5",
        "hour": begin + timedelta(hours=hour), "events": 1,
    } for hour in range(48)])
    repo.audit("system", "hunt.sweep_summary", "h1", {
        "finished": True, "complete": False, "partial_reasons": [], "stats": {},
        "internal_networks": {"outside": 2, "examples": ["198.51.100.7", "198.51.100.8"]},
    })

    summary = run_baseline_stage(repo, "h1", WINDOW, source=EmptyHistory())

    rollup = next(cell for cell in repo.rule_cells("h1")
                  if cell["rule_id"] == ext.id and cell["target"] == "*" and cell["partition"] == "window")
    assert rollup["state"] == "evaluated_partial"
    assert any("outside the internal-network definition" in reason for reason in rollup["detail"]["reasons"])
    assert "outside the internal-network definition" in summary["specs"][ext.id]["window_failure"]


def test_a_rate_judgement_after_its_material_was_released_is_unresolved():
    from romulus.baseline.playbook import ServiceExecRateBaseline

    rate = SPEC_BY_ID["bl.svc_exec_rate"]
    repo = _repo(spec_ids=(rate.id,))
    repo.release_baseline_window_material(
        "h1", rate.id, "host-index",
        "retained window material exceeded the disk budget of 1 bytes; the oldest is released first",
    )
    view = SnapshotView(repo, "h1", WINDOW, {"digest": "snap", "plan": {}, "coverage": {}}, min_live_hours=48,
                        networks_configured=True)

    failure = view._window_failure(ServiceExecRateBaseline())

    assert failure.startswith("window counter material was released before judgement")
