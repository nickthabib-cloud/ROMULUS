"""Storage bounds preserve native evidence and episode replay without timing claims."""
from __future__ import annotations

import hashlib

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.zeek_rate_state import _RecordingDB
from romulus.evidence.typed import fv
from tests.test_zeek_rate_state import event, toy


@pytest.mark.parametrize("many_refs", [True, False])
def test_one_event_cannot_make_a_hunt_sized_recovery_journal(monkeypatch, many_refs):
    rule = toy(threshold=2000)
    peak = 0
    original = _RecordingDB.execute

    def measured(self, *args, **kwargs):
        nonlocal peak
        result = original(self, *args, **kwargs)
        peak = max(peak, len(self.statements))
        return result

    monkeypatch.setattr(_RecordingDB, "execute", measured)
    try:
        if many_refs:
            list(rule.consume([event("many", refs=[f"native-{n}" for n in range(1000)])]))
        else:
            list(rule.consume([event(str(n), member=str(n)) for n in range(1000)]))
            list(rule.consume([event("after-expiry", 100)]))
        assert peak <= 600, peak
        assert rule.rows.store().db.execute("SELECT SUM(weight) FROM history").fetchone()[0] == (
            1000 if many_refs else 1001)
    finally:
        rule.release_state()


def test_partition_storage_checks_are_batched_and_final_rows_committed(monkeypatch):
    rule = toy(threshold=1000)
    try:
        spill = rule.rows.store()
        calls = {"cap": 0, "touch": 0}
        transactions = {"BEGIN": 0, "SAVEPOINT": 0}

        def transaction(statement):
            command = statement.split(None, 1)[0]
            if command in transactions:
                transactions[command] += 1

        spill.db.set_trace_callback(transaction)
        for name in calls:
            original = getattr(spill, name)

            def counted(*args, _name=name, _original=original, **kwargs):
                calls[_name] += 1
                return _original(*args, **kwargs)

            monkeypatch.setattr(spill, name, counted)
        assert not list(rule.consume([event(str(n), n) for n in range(513)]))
        assert not spill.db.in_transaction
        assert spill.db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 513
        assert calls["cap"] <= 16 and calls["touch"] <= 32, calls
        assert transactions["BEGIN"] <= 16 and transactions["SAVEPOINT"] == 0, transactions
        assert not list(rule.finalize())
        assert not spill.db.in_transaction
    finally:
        rule.release_state()


def test_success_history_is_reference_only_even_for_large_citation_fields():
    rule = toy()
    rule.citation_fields += ("large.success",)
    rule.success_fields = ("observer.name", "source.ip", "toy.member", "toy.role")
    try:
        row = event("success", 3, role="success")
        row.fields["large.success"] = fv("".join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(2000)),
                                          "success:native.large")
        assert not list(rule.consume([row]))
        db = rule.rows.store().db
        assert db.execute("SELECT payload FROM history WHERE role='success'").fetchone()[0] is None
        # Late attempts still prove the real success witness during ordered replay.
        list(rule.consume([event("a", 0), event("b", 1), event("c", 2)]))
        high = list(rule.finalize())[-1]
        assert high.proposed_lane == "high"
        [success] = [item for item in high.events if item.id == "success"]
        assert "large.success" not in success.fields
        assert success.get("toy.member") == "alice"
        assert success.fields["toy.member"].origin == row.fields["toy.member"].origin
        assert [ref.key for ref in success.raw] == ["native/success"]
    finally:
        rule.release_state()


def test_real_sqlite_full_preserves_accepted_prefix_and_recovers(monkeypatch, tmp_path):
    rule = toy(threshold=1000)
    rule.budget = StateBudget(tmp_path, disk_total=64 * 1024 * 1024, reserve=0)
    try:
        spill = rule.rows.store()
        original = spill.cap

        def capped():
            original()
            pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
            spill.db.execute(f"PRAGMA max_page_count={pages + 8}")
            spill._budget_limited = True

        monkeypatch.setattr(spill, "cap", capped)
        rows = [event(str(n), n) for n in range(160)]
        assert not list(rule.consume(rows))
        retained = spill.db.execute("SELECT id FROM history ORDER BY id").fetchall()
        assert retained and len(retained) < len(rows)
        assert rule.capped and any("history" in text.lower() for text in rule.limit_reasons())
        assert not spill.db.in_transaction
        monkeypatch.setattr(spill, "cap", original)
        rule.budget._capacity_generation += 1
        assert not list(rule.consume(rows))
        assert spill.db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == len(rows)
        assert spill.db.execute("SELECT COUNT(*) FROM raw_refs").fetchone()[0] == len(rows)
        assert spill.db.execute("SELECT SUM(weight) FROM history").fetchone()[0] == len(rows)
        assert not list(rule.finalize())
    finally:
        rule.release_state()


@pytest.mark.slow
def test_one_hundred_thousand_success_rows_have_bounded_disk_payload_and_native_refs(tmp_path):
    rule = toy(threshold=100001)
    rule.budget = StateBudget(tmp_path, disk_total=128 * 1024 * 1024, reserve=0)
    rule.citation_fields += ("large.success",)
    rule.success_fields = ("source.ip", "toy.member", "toy.role")
    large = "".join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(256))
    try:
        for offset in range(0, 100000, 500):
            rows = [event(f"success-{n}", n, role="success") for n in range(offset, offset + 500)]
            for row in rows:
                row.fields["large.success"] = fv(large, f"{row.id}:native.large")
            assert not list(rule.consume(rows))
        spill = rule.rows.store()
        db = spill.db
        assert db.execute("SELECT COUNT(*),COUNT(payload) FROM history").fetchone() == (100000, 0)
        assert db.execute("SELECT COUNT(*) FROM success_proofs").fetchone()[0] == 100000
        assert db.execute("SELECT COUNT(*) FROM raw_refs").fetchone()[0] == 100000
        assert db.execute("SELECT COUNT(*) FROM episodes").fetchone()[0] == 0
        assert db.execute("SELECT target,native_id FROM raw_refs WHERE id='success-99999'").fetchone() == (
            "native", "success-99999")
        assert not db.execute("SELECT 1 FROM success_proofs WHERE proof LIKE '%large.success%' LIMIT 1").fetchone()
        size = spill.path.stat().st_size
        print(f"Retained history=100000, success_proofs=100000, native_refs=100000, disk_bytes={size}")
        assert size < 96 * 1024 * 1024
        assert not rule.capped
        assert not list(rule.finalize())
        assert not db.in_transaction
    finally:
        rule.release_state()
