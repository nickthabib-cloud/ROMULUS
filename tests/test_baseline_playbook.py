"""Baseline playbooks accumulate window cells but publish only when judged."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.baseline.playbook import BASELINE_PLAYBOOKS
from romulus.baseline.spec import KeyContext
from romulus.detect.registry import fresh_direct_pack, fresh_pack, pack_manifest, rule_kind
from romulus.evidence.typed import Outcome, TypedEvent, fv

T0 = datetime(2026, 1, 2, 12, tzinfo=UTC)


def _exec(event_id: str = "exec-1") -> TypedEvent:
    return TypedEvent(
        id=event_id,
        family="process_exec",
        ts=T0,
        host="Web01",
        outcome=Outcome.success,
        fields={
            name: fv(value, f"fixture:{name}")
            for name, value in {
                "process.executable": "/bin/sh",
                "process.exec_file.path": "/bin/sh",
                "process.user": "www-data",
            }.items()
        },
        raw=[],
        normalizer="fixture@1",
    )


def test_baseline_pack_registers_only_the_s5_specs_and_never_enters_direct_pivots():
    expected = {"bl.ssh_tuple", "bl.exec_path", "bl.exec_pair", "bl.cmd_shape", "bl.ext_dest"}

    assert {playbook.spec.id for playbook in BASELINE_PLAYBOOKS} == expected
    assert {playbook.id for playbook in fresh_pack()} >= expected
    assert not ({playbook.id for playbook in fresh_direct_pack()} & expected)
    manifest = {row["id"]: row["kind"] for row in pack_manifest()}
    assert {spec_id: manifest[spec_id] for spec_id in expected} == {
        spec_id: "baseline" for spec_id in expected
    }
    # rule_kind is the legacy expansion scheduling hook. Baseline rules retain their declared kind in the
    # catalog but share the non-anchor scheduling category with context rules.
    assert {rule_kind(spec_id) for spec_id in expected} == {"context"}


def test_consume_accumulates_one_cell_without_publishing_and_keeps_the_first_event():
    playbook = next(cls() for cls in BASELINE_PLAYBOOKS if cls.spec.id == "bl.exec_path")
    playbook.begin_cell("window-cell", (T0, T0 + timedelta(minutes=5)), KeyContext())

    assert playbook.consume([_exec()]) == []
    cell = playbook.finish_cell()

    assert cell.spec_id == "bl.exec_path"
    assert cell.partial is False
    assert cell.reasons == ()
    assert cell.pendings == ()
    assert [
        {
            "scope_kind": row["scope_kind"],
            "scope": row["scope"],
            "window_count": row["window_count"],
            "first_event_id": row["first_event_id"],
        }
        for row in cell.observations
    ] == [
        {"scope_kind": "account", "scope": "account:www-data", "window_count": 1,
         "first_event_id": "exec-1"},
        {"scope_kind": "host", "scope": "host:web01", "window_count": 1,
         "first_event_id": "exec-1"},
    ]


def test_judge_delegates_to_the_snapshot_view_only_after_accumulation():
    playbook = next(cls() for cls in BASELINE_PLAYBOOKS if cls.spec.id == "bl.exec_path")

    class View:
        def __init__(self):
            self.seen = None

        def judge(self, item):
            self.seen = item
            return ["judged"]

    view = View()

    assert playbook.judge(view) == ["judged"]
    assert view.seen is playbook
    assert playbook.finalize() == []

