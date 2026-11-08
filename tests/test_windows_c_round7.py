"""Retained pressure plans and recoverable physical-capacity refusals."""
import random
import sqlite3
from datetime import timedelta

import pytest

from romulus.detect.bounded import CitationUnavailable, KeyedStore, Spill, StateBudget
from romulus.detect.citing import citation_group, uncited_positive
from romulus.detect.network import PortScan
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from tests.test_bounded_budget import _owner
from tests.test_bounded_starvation import _Listed
from tests.test_flow_rules import eve
from tests.test_sweep import _complete, _repo
from tests.test_windows_c_burst_review import START
from tests.test_windows_c_round4 import dns
from tests.test_windows_c_round5 import _feed, _native_sweep


def test_foreign_reclamation_coalesces_only_until_real_file_release(tmp_path):
    from romulus.hunt.stage import EventStage

    results = []
    for coalesce in (False, True):
        budget = StateBudget(tmp_path, disk_total=4*2**20, reserve=0)
        stage, writer = EventStage(tmp_path, budget=budget), Spill(tmp_path, budget)
        try:
            events = [dns(number, f"native{number}.c2.test")[0] for number in range(128)]
            stage.put(events, {})
            writer.table("state", "body BLOB")
            writer.grew()
            account = stage._citation_account
            account.evict_references = None
            steps = []
            def reclaim(_needed, budget=budget, stage=stage, steps=steps):
                before = budget.physical_used
                ids = stage.db.execute("SELECT id FROM event ORDER BY seq LIMIT 4").fetchall()
                if ids:
                    with stage.db:
                        stage.db.executemany("DELETE FROM event WHERE id=?", ids)
                else:
                    stage.db.execute("PRAGMA incremental_vacuum").fetchall()
                stage.charge_growth()
                steps.append((tuple(identity for identity, in ids), before-budget.physical_used))
                return 4096 if ids or budget.physical_used < before else 0
            account.evict = reclaim
            # A failed writer batch can leave some global room after rollback. Its applied cap
            # still proves that unchanged foreign bytes cannot enlarge its next allocation.
            budget.disk_total = budget.physical_used+writer._page
            failures, calls = 0, []
            while True:
                writer.cap()
                assert writer._cap_global == (writer.db, writer.path, budget.disk_total, budget.reserve)
                try:
                    with writer.db:
                        writer.db.execute("INSERT INTO state VALUES (?)", (bytes(range(256))*64,))
                    writer.grew()
                    break
                except sqlite3.OperationalError as error:
                    assert "full" in str(error).lower()
                    failures += 1
                    writer.db.rollback()
                    writer.grew()
                    first = len(steps)
                    assert budget.reclaim_citations_step(
                        writer_db=writer.db, writer_path=writer.path, writer_page=writer._page,
                        writer_cap=writer._cap_global if coalesce else None,
                        writer_current=lambda writer=writer: (writer.db, writer.path))
                    calls.append(steps[first:])
                    assert budget.physical_used <= budget.disk_total
                    if coalesce:
                        # No successful reclamation step after the first physical decrease.
                        assert all(delta == 0 for _ids, delta in calls[-1][:-1])
                        assert calls[-1][-1][1] > 0
                    else:
                        assert len(calls[-1]) == 1
            assert failures and writer.db.execute("SELECT length(body) FROM state").fetchall() == [(16384,)]
            assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert writer.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            results.append((steps, stage.db.execute("SELECT id FROM event ORDER BY id").fetchall(), failures))
        finally:
            writer.close()
            stage.close()
    assert results[0][:2] == results[1][:2]
    assert results[1][2] < results[0][2]


@pytest.mark.parametrize("identity", ["same", "alias", "unknown", "unknown_volume", "reserve", "stale_cap"])
def test_reclamation_retries_immediately_when_foreign_cap_proof_is_absent(tmp_path, monkeypatch, identity):
    from romulus.hunt.stage import EventStage

    budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    stage, writer = EventStage(tmp_path, budget=budget), Spill(tmp_path, budget)
    alias = None
    try:
        stage.put([dns(number, f"retry{number}.c2.test")[0] for number in range(8)], {})
        writer.table("state", "body BLOB")
        writer.grew()
        budget.disk_total = budget.physical_used+writer._page
        if identity == "unknown_volume":
            monkeypatch.setattr(budget, "headroom", lambda: None)
        elif identity == "reserve":
            monkeypatch.setattr(budget, "headroom", lambda: 0)
        writer.cap()
        cap = writer._cap_global
        if identity in ("unknown_volume", "reserve"):
            assert cap is None
        if identity == "stale_cap":
            budget.reserve += 1
        target, path = writer.db, writer.path
        if identity == "same":
            target, path = stage.db, stage.path
        elif identity == "alias":
            alias = sqlite3.connect(stage.path)
            target, path = alias, stage.path
        if identity in ("same", "alias"):
            cap = (target, path, budget.disk_total, budget.reserve)
        if identity == "unknown":
            stage._citation_account.reclaim_database = None
        calls = []
        def reclaim(_needed):
            calls.append(1)
            with stage.db:
                stage.db.execute("DELETE FROM event WHERE id=(SELECT id FROM event LIMIT 1)")
            stage.charge_growth()
            return 1
        stage._citation_account.evict, stage._citation_account.evict_references = reclaim, None
        before = budget.physical_used
        assert budget.reclaim_citations_step(writer_db=target, writer_path=path, writer_page=writer._page,
                                             writer_cap=cap)
        assert calls == [1] and budget.physical_used == before and stage.count() == 7
    finally:
        if alias is not None:
            alias.close()
        writer.close()
        stage.close()


@pytest.mark.parametrize("change", ["scope", "rows", "schema", "connection"])
@pytest.mark.parametrize("reclaimed", [0, 1])
def test_foreign_callback_changes_force_retry_even_without_reclaimed_rows(tmp_path, change, reclaimed):
    from romulus.hunt.stage import EventStage

    budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    stage, writer = EventStage(tmp_path, budget=budget), Spill(tmp_path, budget)
    try:
        writer.table("state", "body BLOB")
        writer.cap()
        current = [writer.db, writer.path]
        calls = []
        def reclaim(_needed):
            calls.append(1)
            if change == "scope":
                budget.disk_total += 4096
            elif change == "rows":
                with writer.db:
                    writer.db.execute("INSERT INTO state VALUES (?)", (b"changed",))
            elif change == "schema":
                writer.db.execute("CREATE TABLE changed (id INTEGER)")
            else:
                current[:] = [stage.db, stage.path]
            return reclaimed
        stage._citation_account.evict, stage._citation_account.evict_references = reclaim, None
        assert budget.reclaim_citations_step(
            writer_db=writer.db, writer_path=writer.path, writer_page=writer._page,
            writer_cap=writer._cap_global, writer_current=lambda: tuple(current))
        assert calls == [1]
    finally:
        writer.close()
        stage.close()


def test_unsuccessful_sqlite_cap_application_cannot_reuse_earlier_proof(tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    writer = Spill(tmp_path, budget)
    connection = writer.db
    try:
        writer.table("state", "body BLOB")
        writer.cap()
        assert writer._cap_global is not None
        class FailedCap:
            def execute(self, statement):
                if "max_page_count" in statement:
                    raise sqlite3.OperationalError("injected refused page-cap application")
                return connection.execute(statement)
        writer.db = FailedCap()
        writer.cap()
        assert writer._cap_global is None
    finally:
        writer.db = connection
        writer.close()


def test_ceiling_writes_reuse_reference_plan_and_exhaustion(tmp_path, monkeypatch):
    from romulus.hunt import stage as stage_module

    routine = PortScan()
    routine.groups.hot_size = routine.requests.hot_size = 1
    budget = StateBudget(tmp_path, disk_total=4*2**20, reserve=0)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    def feed(start, count):
        hits = [eve(f"flow-{i}", src=f"10.{i//65536}.{i//256%256}.{i%256}", dport=200+i%50)
                for i in range(start, start+count)]
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(hits))
    try:
        feed(0, 400)
        stage = sweep._event_stage()
        while stage._evict_citations(4096):
            pass
        budget.disk_total = budget.physical_used
        compressed = []
        compact = stage_module.compact_event
        def counted(event):
            compressed.append(event.id)
            return compact(event)
        monkeypatch.setattr(stage_module, "compact_event", counted)
        for batch in range(12):
            feed(400+batch*20, 20)
        # Kept and held admissions may each pack once; recursive FULL subdivisions must reuse bytes.
        assert len(compressed) <= 4*12*20
        assert stage._reference_plan_builds <= 3
        assert budget.physical_used <= budget.disk_total
        before = stage._reference_plan_builds
        scanned = stage._reference_rows_visited
        retained = stage.count()
        for _ in range(20):
            with budget.reclamation_write():
                while stage._evict_references(4096):
                    pass
        assert stage._reference_plan_builds == before
        assert stage._reference_rows_visited-scanned <= 2*retained
    finally:
        sweep.close_stage()


def test_native_scale4_releases_use_global_room_without_poisoning_later_findings(tmp_path, monkeypatch):
    from tests import throughput_fixture as fixture

    fixture.patched_sizes(monkeypatch)
    # SQLite's page use depends on the order of the stored event ids, which the evidence epoch hashes: at exactly
    # 4 MiB the epoch-16 layout leaves no room for one correlation finding (the epoch-15 layout did). 4.1 MiB holds
    # the same 60 findings as epoch 15 at 4 MiB, identical apart from id-derived lineage keys. Epoch 17 rehashes the
    # event ids again: the same 60 findings, and with the evidence version set back to 16 the earlier digest.
    budget = StateBudget(tmp_path, disk_total=int(4.1*2**20), reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    snapshot = fixture.run_stack(tmp_path, docs=fixture.build(4))
    assert not budget.broken
    # Shared state retains prior groups and restores SSH/login findings plus alert-linked context.
    # The alert keeps its computed HIGH lane with explicit partial citation coverage at this physical cap.
    assert len(snapshot["candidates"]) == 60
    assert fixture.digests(snapshot)["candidates"] == (
        "0c9ee81e265463ce6d3e9fb7f96bb5ecaef2cffda97e254fccc0a3b75c6ed1c5")
    assert any(row["rule_id"] == "host.shell_spawned_by_connected_process" and row["event_ids"]
               for row in snapshot["candidates"])


def test_native_scale4_at_a_page_tight_cap_refuses_instead_of_failing(tmp_path, monkeypatch):
    """At exactly 4 MiB a citation reclaim's delete needs a page the cap no longer allows: the stage rolls the
    delete back and reports nothing reclaimed, and the hunt finishes (it never fails on that SQLITE_FULL)."""
    from tests import throughput_fixture as fixture

    fixture.patched_sizes(monkeypatch)
    budget = StateBudget(tmp_path, disk_total=4*2**20, reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    snapshot = fixture.run_stack(tmp_path, docs=fixture.build(4))
    assert not budget.broken
    assert len(snapshot["candidates"]) >= 59
    assert any(row["rule_id"] == "host.shell_spawned_by_connected_process" and row["event_ids"]
               for row in snapshot["candidates"])


def test_release_real_sqlite_full_rolls_back_every_relation_and_bookkeeping(tmp_path):
    from romulus.hunt.stage import EventStage

    budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    stage = EventStage(tmp_path, budget=budget)
    pairs = [dns(number, f"release{number}.c2.test") for number in range(3)]
    events = [event for event, _hit in pairs]
    try:
        stage.hold([("first", event) for event in events],
                   {event.raw[0].key: hit["_source"] for event, hit in pairs})
        stage.hold([("second", events[0])], {})
        # Explicit fault injection: a real SQLite allocation inside the release transaction
        # exhausts the actual global page limit. No OperationalError is fabricated.
        stage.db.execute("CREATE TABLE release_pressure (body BLOB)")
        stage.db.execute("CREATE TRIGGER release_allocation BEFORE DELETE ON event BEGIN "
                         "INSERT INTO release_pressure VALUES (zeroblob(131072)); END")
        stage.db.commit()
        stage.charge_growth()
        tables = ("event", "hold", "event_raw", "citation_owner", "raw", "release_pressure")
        before = {table: stage.db.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
        metadata = (stage._text_rows, dict(stage._raw_revisions))
        budget.disk_total = budget.physical_used
        with pytest.raises(sqlite3.OperationalError, match="full"):
            stage.release("first", [event.id for event in events])
        assert not stage.db.in_transaction
        assert before == {table: stage.db.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
        assert (stage._text_rows, dict(stage._raw_revisions)) == metadata
        assert budget.physical_used <= budget.disk_total
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        budget.disk_total = 2*2**20
        stage.release("first", [event.id for event in events])
        assert [event.id for event in stage.load([event.id for event in events])] == [events[0].id]
        assert stage.db.execute("SELECT owner,n FROM hold").fetchall() == [("second", 1)]
        assert set(stage.raw_sources(events)) == {events[0].raw[0].key}
        assert stage.db.execute("SELECT count(*) FROM release_pressure").fetchone()[0] == 2
        assert stage._size == stage.path.stat().st_size
        assert budget.physical_used <= budget.disk_total
    finally:
        stage.close()


def test_large_native_first_batch_pays_to_classify_admissions_beyond_hint_cache(tmp_path, monkeypatch):
    from romulus.hunt.stage import EventStage

    routine, strong = PortScan(), _Listed()
    routine.groups.hot_size = routine.requests.hot_size = 1
    budget = StateBudget(tmp_path, disk_total=400000, reserve=0)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine, strong])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    snapshots = []
    original_plan = EventStage._plan_references
    def plan(stage, token):
        snapshots.append(stage.count())
        return original_plan(stage, token)
    monkeypatch.setattr(EventStage, "_plan_references", plan)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    stage = sweep._event_stage()
    put = stage.put
    def first_admission(events, raw_sources):
        # Force the difficult ordering: all detector groups exist, but no citation is admitted.
        # This must not depend on which preceding state write happens to encounter FULL first.
        if not snapshots:
            before_groups = stage._reference_groups_visited
            stage._plan_references(object())
            assert stage._reference_groups_visited-before_groups >= count
        return put(events, raw_sources)
    monkeypatch.setattr(stage, "put", first_admission)
    count = 10000
    hits = [eve(f"large-flow-{i}", src=f"10.{i//65536}.{i//256%256}.{i%256}", dport=200+i%50)
            for i in range(count)]
    random.Random(19).shuffle(hits)
    try:
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(hits))
        stage = sweep._event_stage()
        assert snapshots[0] == 0 and any(rows > 0 for rows in snapshots[1:])
        assert stage.db.execute("SELECT count(*) FROM event WHERE (reclaim&3)=1").fetchone()[0] > 0
        assert stage._reference_plan_builds <= 4
        assert stage._reference_plan_work+stage._reference_rows_visited <= 30*count
        _feed(sweep, [dns(60000, "late.c2.test")], monkeypatch)
        assert budget.physical_used <= budget.disk_total
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        sweep.finalize()
        [finding] = sweep.repo.candidates("h1")
        assert finding["rule_id"] == strong.id and finding["lane"] == "high" and finding["event_ids"]
    finally:
        sweep.close_stage()


def test_physical_refusal_recovers_after_another_store_releases_room(tmp_path):
    budget = StateBudget(tmp_path, disk_total=180000, reserve=0)
    owner = _owner(tmp_path, budget, "recovering")
    other = _owner(tmp_path, budget, "releasable")
    store = KeyedStore(owner, "records", hot=0)
    space = KeyedStore(other, "records", hot=0)
    try:
        for number in range(4):
            assert space.put(str(number), bytes([number])*18000)
            space.trim()
        for number in range(100):
            if not store.put(str(number), bytes([number])*12000):
                break
            store.trim()
        else:
            raise AssertionError("fixture did not reach physical refusal")
        assert budget.full and owner.limits
        refused = dict(budget.full)
        other.close_spill()
        assert store.put("after-release", b"recovered")
        store.trim()
        assert store.peek("after-release") == b"recovered"
        assert refused.items() <= budget.full.items() and owner.limits
        assert budget.physical_used <= budget.disk_total
    finally:
        owner.close_spill()
        other.close_spill()


def test_native_singleton_full_keeps_small_sibling_and_requalifies_after_real_release(tmp_path, monkeypatch):
    import hashlib

    from romulus.evidence.normalize import normalize_hits
    from tests.test_flow_rules import T0

    routine = PortScan()
    budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=T0-timedelta(hours=1), end=START), {}, stage_dir=tmp_path)
    filler_owner = _owner(tmp_path, budget, "temporary_space")
    filler = KeyedStore(filler_owner, "bytes", hot=0)
    def feed(hits):
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(hits))
    try:
        feed([eve(f"warm-{n}", src=f"10.80.0.{n+1}", dport=200) for n in range(10)])
        stage = sweep._event_stage()
        account = sweep._stage_owner_accounts[routine.id]
        while stage._evict_citations(4096):
            pass
        stage._compact_cache([], (account,), drop_raw=True)
        stage.db.execute("PRAGMA incremental_vacuum").fetchall()
        stage.charge_growth()
        assert filler.put("space", bytes(range(256))*2048)
        filler.trim()
        budget.disk_total = budget.physical_used
        assert stage.db.execute("PRAGMA freelist_count").fetchone()[0] == 0

        protocol = "".join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(4096))
        hits = [eve("large-optional", src="10.90.0.1", dport=200, app_proto=protocol),
                eve("small-sibling", src="10.90.0.2", dport=201)]
        events, _skips, errors = normalize_hits(hits)
        assert not errors and len(events) == 2
        large, small = events
        declined = []
        original = stage._defer_refreshable_row
        def defer(event, accounts):
            result = original(event, accounts)
            if result:
                declined.append(event.id)
            return result
        monkeypatch.setattr(stage, "_defer_refreshable_row", defer)
        feed(hits)
        assert large.id in declined and small.id not in declined
        assert stage.load([large.id]) == []
        assert [event.id for event in stage.load([small.id])] == [small.id]
        assert account.name in budget.full
        assert budget.physical_used <= budget.disk_total

        filler_owner.close_spill()
        stage.owners = {large.id: [account]}
        stage.put([large], {})
        stage.owners = {}
        [recovered] = stage.load([large.id])
        assert recovered.id == large.id and recovered.ts == large.ts and recovered.fields == large.fields
        before = len(declined)
        # The same group now crosses both sample fullness and the publication threshold, with
        # earlier event times. It must use its current facts and preserve real span/native witnesses.
        feed([eve(f"threshold-{n}", src="10.90.0.1", dport=200+n,
                  start=T0-timedelta(minutes=n)) for n in range(1, 25)])
        assert len(declined) == before
        assert budget.physical_used <= budget.disk_total
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        sweep.finalize()
        [finding] = sweep.repo.candidates("h1")
        assert finding["rule_id"] == routine.id and finding["lane"] == "lead"
        assert large.id in finding["event_ids"] and len(finding["event_ids"]) >= 20
        assert "25" in finding["claim"] and account.name in budget.full
    finally:
        filler_owner.close_spill()
        sweep.close_stage()


def test_uncited_group_without_any_time_remains_a_named_positive():
    owner, out = _Listed(), []
    with citation_group(owner, out, ("C2-DOM", "domain", "host", "missing.c2.test"), (1, {"ids": ["missing"]})):
        raise CitationUnavailable("native witness unavailable")
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert out[0].ts is None and out[0].citation_unavailable
    assert "citation_time" in owner.limits
    assert "time" in " ".join(out[0].notes).lower()


def test_uncited_group_uses_native_trigger_time():
    owner = _Listed()
    event, _hit = dns(1, "trigger.c2.test")
    match = uncited_positive(owner, ("C2-DOM", "domain", "host", "trigger.c2.test"),
                             (1, {"ids": ["missing"]}), triggering_record=event)
    assert match.ts == event.ts and match.proposed_lane == "high"
    assert "citation_time" not in owner.limits


def test_uncited_group_recovers_time_from_its_retained_native_reference(tmp_path):
    from romulus.hunt.stage import EventStage

    owner = _Listed()
    event, _hit = dns(1, "retained-time.c2.test")
    stage = EventStage(tmp_path)
    try:
        stage.put([event], {})
        owner.bind_loader(stage.load)
        match = uncited_positive(owner, ("C2-DOM", "domain", "host", "retained-time.c2.test"),
                                 (1, {"ids": [event.id]}))
        assert [item.id for item in match.events] == [event.id]
        assert match.ts == event.ts and match.proposed_lane == "high"
        assert "citation_time" not in owner.limits
        assert "time is unavailable" not in " ".join(match.notes)
        assert "citation_reference" in owner.limits
    finally:
        stage.close()


def test_uncited_factory_split_resolves_each_findings_own_native_or_computed_time():
    from dataclasses import replace

    owner = _Listed()
    event, _hit = dns(1, "factory-time.c2.test")
    computed = event.ts+timedelta(hours=1)
    owner.uncited_finding = lambda key, state, match: [
        replace(match, group_key="", events=[event]),
        replace(match, group_key="computed", events=[event], ts=computed),
        replace(match, group_key="unknown"),
    ]
    native, known, missing = uncited_positive(owner, "split", {"ids": []})
    assert native.ts == event.ts and known.ts == computed and missing.ts is None
    assert [item.id for item in native.events] == [event.id]
    assert "time is unavailable" not in " ".join(native.notes+known.notes)
    assert "time is unavailable" in " ".join(missing.notes)
    assert "Group unknown" in owner.limits["citation_time"].text


def test_native_group_update_protects_old_references_without_rebuilding(tmp_path, monkeypatch):
    rule, sweep = _native_sweep(tmp_path, monkeypatch, total=2**20)
    pairs = [dns(number, "changing.c2.test") for number in range(1, 6)]
    try:
        _feed(sweep, pairs, monkeypatch)
        stage = sweep._event_stage()
        before = stage._reference_plan_builds
        _feed(sweep, [dns(60, "changing.c2.test")], monkeypatch)
        assert stage._reference_plan_builds == before
        while stage._evict_references(4096):
            pass
        assert {event.id for event in stage.load([event.id for event, _hit in pairs])} == {
            event.id for event, _hit in pairs}
        sweep.finalize()
        [candidate] = sweep.repo.candidates("h1")
        assert candidate["rule_id"] == rule.id and candidate["lane"] == "high" and candidate["event_ids"]
    finally:
        sweep.close_stage()


def test_reacquired_native_reference_and_unclassified_rows_survive_old_plan(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, total=2**20)
    pairs = [dns(number, "shared.c2.test") for number in range(1, 6)]
    try:
        _feed(sweep, pairs, monkeypatch)
        stage = sweep._event_stage()
        [(identity,)] = stage.db.execute("SELECT id FROM event WHERE reclaim=133 ORDER BY citation_epoch(body),id LIMIT 1").fetchall()
        [shared] = stage.load([identity])
        unknown = sweep.budget.account("new_reader:citations")
        stage.owner_accounts["new_reader"] = unknown
        before = stage._reference_plan_builds
        stage.hold([("new_reader", shared)], {})
        new, _hit = dns(90, "unclassified.example.test")
        stage._put_compact([new], accounts=(unknown,))
        while stage._evict_references(4096):
            pass
        assert stage._reference_plan_builds == before
        assert {event.id for event in stage.load([identity, new.id])} == {identity, new.id}
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        sweep.close_stage()


def test_shuffled_protection_at_actual_full_keeps_every_native_reference(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, total=64*2**20)
    try:
        for start in range(0, 6000, 1000):
            _feed(sweep, [dns(number, f"group{number//20}.c2.test")
                          for number in range(start, start+1000)], monkeypatch)
        stage = sweep._event_stage()
        while stage._evict_citations(4096):
            pass
        stage._plan_references(object())
        before = stage.db.execute("PRAGMA page_count").fetchone()[0]
        sweep.budget.disk_total = sweep.budget.physical_used
        stage.db.execute(f"PRAGMA max_page_count={before}")
        identities = [row[0] for row in stage.db.execute("SELECT id FROM event WHERE reclaim=133 ORDER BY citation_epoch(body),id")]
        assert len(identities) == 5700
        random.Random(4).shuffle(identities)
        for identity in identities:
            stage._protect_ids([identity])
        assert stage.db.execute("PRAGMA page_count").fetchone()[0] == before
        assert stage.db.execute("SELECT count(*) FROM event WHERE reclaim=133").fetchone()[0] == 0
        assert stage.db.execute("SELECT count(*) FROM event").fetchone()[0] == 6000
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        sweep.close_stage()


def test_admission_sequence_exhaustion_is_named_and_compaction_keeps_order(tmp_path):
    from romulus.hunt.stage import MAX_REFERENCE_SEQUENCE, EventStage
    stage = EventStage(tmp_path)
    pairs = [dns(number, f"sequence{number}.c2.test") for number in range(4)]
    try:
        stage.put([event for event, _hit in pairs[:2]], {})
        before = stage.db.execute("SELECT id,seq FROM event ORDER BY id").fetchall()
        while stage._evict_citations(4096):
            pass
        assert stage.db.execute("SELECT id,seq FROM event ORDER BY id").fetchall() == before
        stage._reference_serial = MAX_REFERENCE_SEQUENCE-1
        stage.put([event for event, _hit in pairs[2:]], {})
        assert "admission sequence exhausted" in stage.refusal_reason
        assert stage.refused == 2 and stage.count() == 2
    finally:
        stage.close()


def test_unknown_native_rows_pay_for_amortized_plans_without_losing_any_reference(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, total=16*2**20)
    try:
        _feed(sweep, [dns(number, "retained.c2.test") for number in range(1, 6)], monkeypatch)
        stage = sweep._event_stage()
        stage.owner_accounts["unknown_reader"] = sweep.budget.account("event_stage:unknown_reader")
        identities = []
        for start in range(1024, 2048, 64):
            events = [dns(number, f"unknown{number}.example.test")[0] for number in range(start, start+64)]
            identities.extend(event.id for event in events)
            stage.hold([("unknown_reader", event) for event in events], {})
            while stage._evict_references(4096):
                pass
        assert len(stage.load(identities)) == 1024
        # Supplied admission/owner lookups now pay for scans as well as successful growth.
        assert stage._reference_plan_builds <= 6
        assert stage._reference_plan_work+stage._reference_rows_visited <= 20*len(identities)
        assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        sweep.finalize()
        [candidate] = sweep.repo.candidates("h1")
        assert candidate["lane"] == "high" and candidate["event_ids"]
    finally:
        sweep.close_stage()


def test_shared_publishing_hint_survives_other_store_and_hint_cache_pressure(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, total=16*2**20)
    owner = _owner(tmp_path, sweep.budget, "mixed_groups")
    owner.refreshes_citation_on_next_record = lambda store, state: not state["publish"]
    publishing = KeyedStore(owner, "publishing", hot=1, candidate=lambda state: state["publish"])
    routine = KeyedStore(owner, "routine", hot=1, candidate=lambda state: state["publish"])
    try:
        _feed(sweep, [dns(1, "sentinel.c2.test")], monkeypatch)
        stage = sweep._event_stage()
        stage.playbooks = (*stage.playbooks, owner)
        account = sweep.budget.account("mixed_groups:citations")
        stage.owner_accounts[owner.id] = account
        event, _hit = dns(2, "shared.example.test")
        assert publishing.put("positive", {"publish": True, "ids": [event.id]})
        publishing.trim(0)
        stage._flush_reference_states()
        for number in range(8193):
            assert publishing.put(number, {"publish": True, "ids": [f"pending-reference-{number}"]})
            if number % 64 == 63:
                publishing.trim(0)
        stage._flush_reference_states()
        assert routine.put("routine", {"publish": False, "ids": [event.id]})
        stage._flush_reference_states()
        stage.hold([(owner.id, event)], {})
        while stage._evict_references(4096):
            pass
        assert [kept.id for kept in stage.load([event.id])] == [event.id]
        assert stage._owner_number(account.name) in stage._reference_uncertain_owners
    finally:
        owner.close_spill()
        sweep.close_stage()
