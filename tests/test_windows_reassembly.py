"""Disk-backed PowerShell script-block reassembly contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import batched

import pytest

from romulus.detect.bounded import StateBudget
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS
from romulus.evidence.windows_reassembly import ScriptBlockAssembler

NOW = datetime(2026, 10, 26, 17, 0, tzinfo=UTC)


def _part(
    number: int, total: int, text: str, *, native: str | None = None, block: str = "block-a",
) -> TypedEvent:
    native = native or f"part-{number}"
    ref = RawRef(target="windows", native_id=native, digest=native)
    return TypedEvent(
        id=f"event-{native}", family="script_block", ts=NOW + timedelta(seconds=number), host="ws01",
        outcome=Outcome.success,
        fields={
            "event.code": fv(4104, f"{native}:event_id"),
            "host.os.family": fv("windows", f"{native}:computer"),
            "script.block_id": fv(block, f"{native}:ScriptBlockId"),
            "script.message_number": fv(number, f"{native}:MessageNumber"),
            "script.message_total": fv(total, f"{native}:MessageTotal"),
            "script.text": fv(text, f"{native}:ScriptBlockText"),
            "script.complete": fv(False, f"{native}:part"),
        },
        raw=[ref], normalizer="windows-ecs@3",
    )


def _consume(assembler, events, sources=None):
    """Assertions below concern the joined view; fragment delivery has its own regression proof."""
    return [event for event in assembler.consume(events, sources) if not event.has("script.part_number")]


def test_out_of_order_parts_emit_one_joined_event_with_every_raw_reference(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        assert _consume(assembler, [_part(2, 3, "two")], {"windows/part-2": {"part": 2}}) == []
        assert _consume(assembler, [_part(1, 3, "one")], {"windows/part-1": {"part": 1}}) == []
        output = _consume(assembler, [_part(3, 3, "three")], {"windows/part-3": {"part": 3}})
        assert len(output) == 1
        event = output[0]
        assert event.get("script.text") == "onetwothree"
        assert event.get("script.complete") is True
        assert event.get("script.part_count") == 3
        assert event.get("script.missing_parts") == []
        assert [ref.native_id for ref in event.raw] == ["part-1", "part-2", "part-3"]
        assert assembler.sources_for([event]) == {
            "windows/part-1": {"part": 1},
            "windows/part-2": {"part": 2},
            "windows/part-3": {"part": 3},
        }
    finally:
        assembler.close()


def test_duplicate_parts_count_once_and_conflicts_are_stated(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        _consume(assembler, [_part(1, 2, "first", native="first-copy")])
        _consume(assembler, [_part(1, 2, "first", native="exact-copy")])
        _consume(assembler, [_part(1, 2, "different", native="conflict-copy")])
        event = _consume(assembler, [_part(2, 2, "second")])[0]
        assert event.get("script.text") == "firstsecond"
        assert event.get("script.complete") is False
        assert len(event.raw) == 4
        assert any("conflicting part 1" in caveat for caveat in event.caveats)
        assert _consume(assembler, [_part(2, 2, "second", native="late-copy")]) == []
    finally:
        assembler.close()


def test_conflicting_total_before_emission_makes_the_joined_block_incomplete(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        assert _consume(assembler, [_part(1, 2, "first")]) == []

        [event] = _consume(assembler, [_part(2, 3, "second")])

        assert event.get("script.text") == "firstsecond"
        assert event.get("script.complete") is False
        assert any("conflicting total 3" in caveat for caveat in event.caveats)
    finally:
        assembler.close()


def test_late_conflicting_duplicate_is_returned_as_an_incomplete_part(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        [completed] = _consume(assembler, [_part(1, 1, "first")])
        assert completed.get("script.complete") is True

        [conflict] = _consume(assembler, [_part(1, 1, "changed", native="late-conflict")])

        assert conflict.get("script.complete") is False
        assert any("late conflicting part 1" in caveat for caveat in conflict.caveats)
        assert _consume(assembler, [_part(1, 1, "first", native="late-exact")]) == []
    finally:
        assembler.close()


def test_late_conflicting_total_is_returned_as_an_incomplete_part(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        _consume(assembler, [_part(1, 1, "first")])

        [conflict] = _consume(assembler, [_part(1, 2, "first", native="late-total")])

        assert conflict.get("script.complete") is False
        assert any("late conflicting total 2" in caveat for caveat in conflict.caveats)
    finally:
        assembler.close()


def test_finalize_emits_incomplete_blocks_with_missing_parts(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        _consume(assembler, [_part(3, 4, "tail")])
        _consume(assembler, [_part(1, 4, "head")])
        event = next(assembler.finalize())
        assert event.get("script.complete") is False
        assert event.get("script.missing_parts") == [2, 4]
        assert event.get("script.part_count") == 2
        assert event.get("script.text") == "headtail"
        assert any("missing parts 2, 4" in caveat for caveat in event.caveats)
        assert list(assembler.finalize()) == []
    finally:
        assembler.close()


def test_finalize_streams_pending_blocks_lazily_in_sqlite_order(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    blocks = [f"00000000-0000-0000-0000-{ordinal:012x}" for ordinal in range(257)]
    try:
        for ordinal, block in reversed(list(enumerate(blocks))):
            assert _consume(assembler, [
                _part(1, 2, f"part-{ordinal}", native=f"part-{ordinal}", block=block),
            ], {f"windows/part-{ordinal}": {"part": ordinal}}) == []

        finalized = assembler.finalize()

        assert assembler.db.execute(
            "SELECT count(*) FROM blocks WHERE emitted = 1"
        ).fetchone()[0] == 0
        first = next(finalized)
        assert first.get("script.block_id") == blocks[0]
        assert assembler.sources_for([first]) == {"windows/part-0": {"part": 0}}
        assert assembler.db.execute(
            "SELECT count(*) FROM blocks WHERE emitted = 1"
        ).fetchone()[0] == 1
        statements: list[str] = []
        assembler.db.set_trace_callback(statements.append)
        finalized_blocks = []
        for batch in batched(finalized, 128):
            events = list(batch)
            finalized_blocks.extend(event.get("script.block_id") for event in events)
            assert len(assembler.sources_for(events)) == len(events)
        assert finalized_blocks == blocks[1:]
        assert not any(
            statement.strip()
            == "SELECT target, native_id, source FROM refs WHERE source IS NOT NULL"
            for statement in statements
        )
        assert assembler._emitted_sources == {}
    finally:
        assembler.close()


def test_incomplete_block_uses_the_lowest_available_part_as_its_stable_base(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        _consume(assembler, [_part(3, 4, "tail")])
        _consume(assembler, [_part(2, 4, "middle")])

        event = next(assembler.finalize())

        assert event.ts == NOW + timedelta(seconds=2)
        assert event.get("script.text") == "middletail"
        assert event.get("script.missing_parts") == [1, 4]
    finally:
        assembler.close()


def test_joined_text_cap_keeps_the_ordered_prefix_and_is_incomplete(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, text_cap=20)
    try:
        _consume(assembler, [_part(1, 2, "abcdefghijklmno")])
        event = _consume(assembler, [_part(2, 2, "PQRSTUVWXYZ")])[0]
        assert event.get("script.truncated") is True
        assert len(event.get("script.text")) <= 20
        assert event.get("script.text").startswith("abcdefghi")
        assert event.get("script.text") == "abcdefghijklmnoPQRST"
        assert event.get("script.complete") is False
        assert assembler.partial_reasons
        assert event.get("script.retained_parts") == [1, 2]
        assert any("joined text capped" in caveat for caveat in event.caveats)
    finally:
        assembler.close()


def test_disk_refusal_returns_a_partial_part_instead_of_forgetting_it(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, max_bytes=1)
    try:
        event = _consume(assembler, [_part(1, 2, "first")])[0]
        assert event.get("script.complete") is False
        assert any("reassembly state refused" in caveat for caveat in event.caveats)
        assert assembler.refusal_reason
    finally:
        assembler.close()


def test_state_budget_new_key_refusal_is_exposed_structurally(tmp_path):
    budget = StateBudget(tmp_path, disk_total=1024 * 1024, reserve=0)
    account = budget.account("windows_scripts")
    assembler = ScriptBlockAssembler(tmp_path, budget=budget, account=account)
    budget.force_full("script state test refusal", lambda candidate: candidate is account)
    try:
        [event] = _consume(assembler, [_part(1, 2, "first")])

        assert event.get("script.complete") is False
        assert assembler.refusal_reasons == ("script state test refusal",)
    finally:
        assembler.close()


def test_state_budget_hard_refusal_is_exposed_structurally(tmp_path):
    budget = StateBudget(tmp_path, disk_total=1024 * 1024, reserve=0)
    account = budget.account("windows_scripts")
    assembler = ScriptBlockAssembler(tmp_path, budget=budget, account=account)
    budget.fail("script state disk failed")
    try:
        [event] = _consume(assembler, [_part(1, 2, "first")])

        assert event.get("script.complete") is False
        assert assembler.refusal_reasons == ("script state disk failed",)
    finally:
        assembler.close()


def test_normalizer_marked_incomplete_metadata_stays_incomplete(tmp_path):
    event = _part(1, 2, "first")
    event.fields.pop("script.message_total")
    event.fields["script.complete"] = fv(False, "part-1:incomplete-metadata")
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        [partial] = _consume(assembler, [event], {"windows/part-1": {"part": 1}})

        assert partial.get("script.complete") is False
        assert any("part metadata is incomplete or invalid" in caveat for caveat in partial.caveats)
        assert partial.raw == event.raw
        assert assembler.db.execute("SELECT count(*) FROM blocks").fetchone()[0] == 0
        assert list(assembler.finalize()) == []
    finally:
        assembler.close()


def test_maximum_supported_part_count_enters_bounded_state(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        assert _consume(assembler, [_part(1, SCRIPT_BLOCK_MAX_PARTS, "first")]) == []
        assert assembler.db.execute("SELECT total FROM blocks").fetchone() == (SCRIPT_BLOCK_MAX_PARTS,)
    finally:
        assembler.close()


@pytest.mark.parametrize("total", [SCRIPT_BLOCK_MAX_PARTS + 1, 2**31])
def test_part_count_above_supported_maximum_is_cited_without_entering_state(tmp_path, total):
    event = _part(1, total, "hostile")
    event.fields["script.complete"] = fv(True, "hostile:incorrect-upstream-completeness")
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        [partial] = _consume(assembler, [event], {"windows/part-1": {"part": 1}})

        assert partial.get("script.complete") is False
        assert partial.raw == event.raw
        assert any(
            f"supported maximum {SCRIPT_BLOCK_MAX_PARTS}" in caveat
            for caveat in partial.caveats
        )
        assert assembler.db.execute("SELECT count(*) FROM blocks").fetchone()[0] == 0
        assert assembler.db.execute("SELECT count(*) FROM parts").fetchone()[0] == 0
        assert assembler.db.execute("SELECT count(*) FROM refs").fetchone()[0] == 0
        assert list(assembler.finalize()) == []
    finally:
        assembler.close()


def test_completed_blocks_release_their_large_part_and_raw_payload_rows(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, max_bytes=256 * 1024)
    try:
        for ordinal in range(300):
            block = f"00000000-0000-0000-0000-{ordinal:012x}"
            [completed] = _consume(assembler, [
                _part(1, 1, "x" * 512, native=f"part-{ordinal}", block=block),
            ], {f"windows/part-{ordinal}": {"payload": "y" * 512}})
            assembler.sources_for([completed])

        assert assembler.refusal_reason == ""
        assert assembler.db.execute("SELECT count(*) FROM parts WHERE text != ''").fetchone()[0] == 0
        assert assembler.db.execute("SELECT max(length(text_digest)) FROM parts").fetchone()[0] == 64
        assert assembler.db.execute("SELECT count(*) FROM refs").fetchone()[0] == 0
        assert assembler.db.execute("SELECT sum(length(base_event)) FROM blocks").fetchone()[0] == 0
    finally:
        assembler.close()


def test_truncated_join_never_withholds_middle_or_last_part_text(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, text_cap=20)
    try:
        output = assembler.consume([
            _part(3, 3, "tail-payload"), _part(2, 3, "Invoke-MiddlePayload"), _part(1, 3, "a" * 20),
        ])
        parts = [event for event in output if event.has("script.part_number")]
        [joined] = [event for event in output if not event.has("script.part_number")]
        assert {event.get("script.text") for event in parts} == {
            "a" * 20, "Invoke-MiddlePayload", "tail-payload",
        }
        assert all(not event.get("script.complete") and event.raw for event in parts)
        assert joined.get("script.text") == "a" * 20
        assert joined.get("script.complete") is False
        assert joined.get("script.retained_parts") == [1]
        assert set(joined.get("script.part_event_ids")) == {event.id for event in parts}
        assert any("cross-part matches" in reason for reason in assembler.partial_reasons)
    finally:
        assembler.close()


def test_join_preserves_a_match_split_across_parts_inside_the_prefix(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, text_cap=20)
    try:
        output = assembler.consume([_part(1, 2, "Invoke-"), _part(2, 2, "Payload" + "x" * 30)])
        [joined] = [event for event in output if not event.has("script.part_number")]
        assert joined.get("script.text").startswith("Invoke-Payload")
        assert not joined.get("script.complete")
    finally:
        assembler.close()


def test_joined_only_boundary_match_cites_parts_beyond_the_source_body_page(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        output = assembler.consume([
            _part(number, 200, "Invoke-" if number == 199 else "Payload" if number == 200 else ".")
            for number in range(1, 201)
        ])
        [joined] = [event for event in output if not event.has("script.part_number")]
        assert "Invoke-Payload" in joined.get("script.text")
        assert all("Invoke-Payload" not in event.get("script.text") for event in output
                   if event.has("script.part_number"))
        assert {ref.native_id for ref in joined.raw} >= {"part-199", "part-200"}
        assert joined.get("script.complete")
    finally:
        assembler.close()


def test_many_duplicate_refs_cannot_displace_the_last_parts_citation(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        assembler.consume([_part(1, 2, "head", native=f"copy-{number}") for number in range(4_100)])
        output = assembler.consume([_part(2, 2, "payload", native="last-part")])
        [joined] = [event for event in output if not event.has("script.part_number")]
        assert "last-part" in {ref.native_id for ref in joined.raw}
        assert len(joined.raw) == 2
        assert joined.get("script.text") == "headpayload"
    finally:
        assembler.close()


def test_reassembly_reopens_pending_state_and_keeps_compact_emitted_identity(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    assembler.consume([_part(2, 2, "tail")])
    assembler.close()
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        output = assembler.consume([_part(1, 2, "head")])
        [joined] = [event for event in output if not event.has("script.part_number")]
        assert joined.get("script.text") == "headtail"
        assert joined.get("script.complete")
        assert assembler.consume([_part(1, 2, "head")]) == []
        assert assembler.db.execute("SELECT sum(length(text)) FROM parts").fetchone()[0] == 0
    finally:
        assembler.close()


@pytest.mark.slow
def test_100k_blocks_stream_above_the_old_fixed_disk_limit(tmp_path):
    import json
    import tracemalloc
    from time import perf_counter

    count, batch_size = 100_001, 512
    budget = StateBudget(tmp_path, disk_total=512 * 2**20, reserve=0)
    assembler = ScriptBlockAssembler(tmp_path, budget=budget)
    commits = 0

    def trace(statement):
        nonlocal commits
        if statement == "COMMIT":
            commits += 1

    assembler.db.set_trace_callback(trace)
    tracemalloc.start()
    started = perf_counter()
    joined_count = 0
    try:
        for number in (1, 2):
            for start in range(0, count, batch_size):
                output = assembler.consume([
                    _part(number, 2, "x" * 512, native=f"{ordinal}-{number}", block=f"block-{ordinal}")
                    for ordinal in range(start, min(count, start + batch_size))
                ])
                joined_count += sum(event.get("script.complete") is True for event in output)
                assembler.sources_for(output)
                assert not assembler.refusal_reasons
        elapsed = perf_counter() - started
        _current, peak = tracemalloc.get_traced_memory()
        print("WINDOWS_SCRIPT_BLOCK_SCALE " + json.dumps({
            "blocks": count, "parts": count * 2, "elapsed_seconds": round(elapsed, 3),
            "peak_bytes": peak, "disk_bytes": assembler._db_size(), "commits": commits,
        }, sort_keys=True))
        assert joined_count == count
        assert assembler._db_size() > 64 * 2**20
        assert peak < 64 * 2**20
        assert commits == 2 * ((count + batch_size - 1) // batch_size)
        assert not list(assembler.finalize())
    finally:
        tracemalloc.stop()
        assembler.close()
