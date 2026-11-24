"""Reference protection stays cheap as detection state grows: the citation walk gives the same ids in the same order
as the walk it replaced, and a row already protected under the current plan is never sent to SQLite again, while
every id still counts as touch work. Growth guards count statements and walk steps, never wall-clock time."""
from __future__ import annotations

import dataclasses

from romulus.detect.bounded import HeldExamples
from romulus.detect.citing import Ends, Named, state_citation_ids
from romulus.detect.hijack import _File, _OkTimes, _Run, _Series, _Write
from romulus.evidence.typed import TypedEvent
from tests.test_windows_c_round4 import dns


def _reference_walk(state):
    """The walker as it was before types were classified once: the order and the ids the new walker must give."""
    from dataclasses import fields, is_dataclass

    reference_names = {"id", "event_id", "ids", "events", "held", "cited", "cites", "examples",
                       "opener_id", "first", "last", "longest", "parts", "staged"}

    def visit(value, references=False):
        if isinstance(value, TypedEvent):
            yield value.id
        elif isinstance(value, (HeldExamples, Ends)):
            yield from value.ids()
        elif isinstance(value, Named):
            yield from value.ids.values()
        elif isinstance(value, str):
            if references:
                yield value
        elif isinstance(value, dict):
            for name, item in value.items():
                yield from visit(item, references or name in reference_names)
        elif isinstance(value, (tuple, list)):
            for item in value:
                yield from visit(item, references)
        elif is_dataclass(value):
            for item in fields(value):
                yield from visit(getattr(value, item.name), item.name in reference_names)
        elif slots := getattr(type(value), "__slots__", ()):
            for name in slots:
                yield from visit(getattr(value, name, None), name in reference_names)

    yield from visit(state)


class _Text(str):
    pass


@dataclasses.dataclass
class _Plain:
    id: str = "plain-id"
    note: str = "not a reference"
    events: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class _Defaults:
    """A dataclass whose fields all have class-level defaults, so its type can be walked as a value."""
    id: str = "class-id"
    note: str = "not a reference"


class _Slotted:
    __slots__ = ("cited", "count", "missing")

    def __init__(self):
        self.cited = ["slot-a", 3, ("slot-b", 1.5)]
        self.count = 7


def _hijack_file(sessions: int) -> _File:
    state = _File()
    state.writes.append(_Write(1.0, "w-1", "/etc/cron.daily/job", "cp", "deploy", "1000", ("boot", "5"), False, False))
    state.kernel_writes.append(_Write(2.0, "k-1", "/etc/cron.daily/job", "kernel", "deploy", "1000", None, False,
                                      False, kernel=True))
    state.changes.append((2.0, "k-1", "deploy", "write"))
    state.counts["deploy"] = [3, 2]
    for session in range(sessions):
        series = _Series(detail=f"session {session}")
        series.ok_ts = _OkTimes()
        for tick in range(70):
            series.ok_ts.add(float(session * 100 + tick))
        series.first.append(_Run(float(session), f"run-{session}-a", "/etc/cron.daily/job", "as the executable", None))
        series.first.append(_Run(float(session), f"run-{session}-b", "/etc/cron.daily/job", "operand", f"auth-{session}"))
        series.after["w-1"] = series.first[0]
        series.after_n["w-1"] = [session, True]
        state.runs[("login", ("boot", str(session)), "0")] = series
    return state


def _states():
    event, _hit = dns(1, "walk.c2.test")
    held = HeldExamples(3)
    held.offer(event)
    ends = Ends()
    ends.offer(1.0, 2.0, "end-a")
    ends.offer(0.5, 3.0, "end-b")
    named = Named(4)
    named.offer("sig", event)
    return [
        _hijack_file(0), _hijack_file(1), _hijack_file(12),
        {"ids": ["a", "b", ("c", 4)], "other": ["not", "references"], ("tuple", "key"): {"cited": "d"}},
        [event, held, ends, named, _Plain(events=[event, "e-id"]), _Slotted()],
        (1, 2.5, None, True, b"bytes", 3j, _Text("text"), {"first": _Text("sub-ref")}),
        {"held": [[1.0, "x"], [2.0, None]], "staged": {"k": "staged-id"}},
        _Defaults, {"examples": _Defaults}, int,     # class objects held as values
        [[[[["deep-not-ref"]]]], {"parts": [[["deep-ref"]]]}],
        {}, [], "loose string", 42,
    ]


def test_walker_gives_the_ids_of_the_walk_it_replaced_in_the_same_order():
    for state in _states():
        assert list(state_citation_ids(state)) == list(_reference_walk(state)), repr(state)[:120]


def test_walker_walks_nothing_until_an_id_is_read(monkeypatch):
    """Protection without a plan never reads the walk it is given, so creating one must cost nothing."""
    from romulus.detect import citing

    steps = []
    original = citing._visit
    monkeypatch.setattr(citing, "_visit", lambda *args: (steps.append(1), original(*args))[1])
    walk = state_citation_ids(_hijack_file(3))
    assert steps == []
    assert list(walk) == list(_reference_walk(_hijack_file(3))) and steps


def _stage(tmp_path, count):
    from romulus.hunt.stage import EventStage

    stage = EventStage(tmp_path)
    events = [dns(number, f"protect{number}.c2.test")[0] for number in range(count)]
    stage.put(events, {})
    stage._plan_references(object())
    return stage, [event.id for event in events]


def _statements(stage):
    seen = []
    stage.db.set_trace_callback(seen.append)
    return seen


def _flags(stage, ids):
    marks = ",".join("?" for _ in ids)
    return dict(stage.db.execute(f"SELECT id, reclaim FROM event WHERE id IN ({marks})", ids))


def test_a_row_protected_under_the_plan_is_not_updated_again_but_still_counts(tmp_path):
    stage, ids = _stage(tmp_path, 300)
    try:
        seen = _statements(stage)
        stage._protect_ids(ids)
        assert all(flag & 2 for flag in _flags(stage, ids).values())
        assert sum(sql.startswith("UPDATE event") for sql in seen) == 3     # 300 ids in chunks of 128
        seen.clear()
        work, touch = stage._reference_work, stage._reference_touch_work
        stage._protect_ids(list(ids) + list(ids))
        assert not [sql for sql in seen if sql.startswith(("UPDATE", "SELECT"))]
        assert stage._reference_work - work == 600 and stage._reference_touch_work - touch == 600
    finally:
        stage.close()


def test_a_new_plan_forgets_what_was_protected(tmp_path):
    stage, ids = _stage(tmp_path, 40)
    try:
        stage._protect_ids(ids)
        stage._plan_references(object())                 # rewrites every row's flags
        flags = _flags(stage, ids)
        unprotected = [identity for identity, flag in flags.items() if not flag & 2]
        assert unprotected
        seen = _statements(stage)
        stage._protect_ids(ids)
        assert any(sql.startswith("UPDATE event") for sql in seen)
        assert all(flag & 2 for flag in _flags(stage, ids).values())
    finally:
        stage.close()


def test_an_id_without_a_row_is_protected_once_its_row_arrives(tmp_path):
    stage, ids = _stage(tmp_path, 4)
    try:
        later, _hit = dns(500, "later.c2.test")
        stage._protect_ids([*ids, later.id])                # no row yet: nothing to protect, nothing remembered
        stage.put([later], {})
        assert not _flags(stage, [later.id])[later.id] & 2
        stage._protect_ids([later.id])
        assert _flags(stage, [later.id])[later.id] & 2
    finally:
        stage.close()


def test_an_absent_id_is_not_resent_until_a_row_is_admitted_by_any_path(tmp_path):
    stage, _ids = _stage(tmp_path, 4)
    try:
        held, _hit = dns(501, "held-later.c2.test")
        compact, _hit = dns(502, "compact-later.c2.test")
        put, _hit = dns(503, "put-later.c2.test")
        absent = [held.id, compact.id, put.id]
        stage._protect_ids(absent)
        seen = _statements(stage)
        work = stage._reference_work
        stage._protect_ids(absent)
        assert not [sql for sql in seen if sql.startswith(("UPDATE", "SELECT"))]
        assert stage._reference_work - work == 3
        stage.hold([("owner", held)], {})
        stage._put_compact([compact])
        stage.put([put], {})
        stage._protect_ids(absent)
        assert all(flag & 2 for flag in _flags(stage, absent).values())
        assert len(_flags(stage, absent)) == 3
    finally:
        stage.close()


def test_a_dropped_and_readmitted_row_is_protected_again(tmp_path):
    from romulus.hunt.stage import EventStage

    stage = EventStage(tmp_path)
    try:
        event, _hit = dns(7, "dropped.c2.test")
        stage.hold([("owner", event)], {})
        stage._plan_references(object())
        stage._protect_ids([event.id])
        assert _flags(stage, [event.id])[event.id] & 2
        stage.release("owner", [event.id])
        assert _flags(stage, [event.id]) == {}
        stage.hold([("owner", event)], {})
        assert not _flags(stage, [event.id])[event.id] & 2
        stage._protect_ids([event.id])
        assert _flags(stage, [event.id])[event.id] & 2
    finally:
        stage.close()


def test_touching_a_growing_state_sends_only_its_new_rows(tmp_path):
    """Growth guard: a state touched again and again while it grows (as a root-run file gains login sessions)
    sends SQLite statements for its new references only, however many it already holds."""
    stage, ids = _stage(tmp_path, 2_000)
    try:
        seen = _statements(stage)
        per_touch = []
        for size in range(100, 2_001, 100):
            seen.clear()
            stage._protect_ids(ids[:size])
            per_touch.append(sum(sql.startswith(("UPDATE event", "SELECT id FROM event")) for sql in seen))
        assert per_touch[0] == 2                           # 100 new ids: one UPDATE chunk, one confirming read
        assert set(per_touch[1:]) == {2}                   # each touch: only its 100 new ids, never the whole state
        assert all(flag & 2 for flag in _flags(stage, ids).values())
    finally:
        stage.close()


def test_hijack_file_walk_counts_containers_and_references_not_kept_times():
    """Growth guard: the walk's steps grow with the series a file holds, never with the 64 run times each keeps."""
    from romulus.detect import citing

    steps = []
    original = citing._visit

    def counting(value, references, out):
        steps.append(1)
        return original(value, references, out)

    citing._visit = counting
    try:
        counts = {}
        for sessions in (1, 11):
            steps.clear()
            assert list(state_citation_ids(_hijack_file(sessions))) == list(_reference_walk(_hijack_file(sessions)))
            counts[sessions] = len(steps)
        per_series = (counts[11] - counts[1]) / 10
        assert per_series < 30, per_series                    # the reference walk visits about 100 per series
    finally:
        citing._visit = original
