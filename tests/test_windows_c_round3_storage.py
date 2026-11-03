"""Round-three production-path authentication storage regressions."""
from datetime import timedelta
from pathlib import Path

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.windows_auth_events import WindowsKerberoastDiversity, WindowsPasswordSpray
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from romulus.hunt import sweep as sw
from romulus.hunt.publish import WindowsCitationFetcher
from romulus.hunt.stage import EventStage
from romulus.sources.models import Window
from romulus.store.repo import raw_id
from tests.test_sweep import _repo
from tests.test_windows_c_burst_review import START, failure, ticket
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run


def native_ticket(n, principal, service, offset, index="logs-windows-fixture"):
    logical = LogicalWindowsEvent("Security", SECURITY, 4769, "dc01.example.test", 100000+n,
        (START+timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
        {"TargetUserName": principal+"@EXAMPLE.TEST", "TargetDomainName": "EXAMPLE.TEST",
         "ServiceName": service, "IpAddress": "203.0.113.5", "TicketEncryptionType": "0x12", "Status": "0x0"})
    hit = windows_hit(logical, "winlogbeat_8")
    hit["_index"] = index
    return normalize_windows(hit), hit


def feed(sweep, rule, pairs):
    events = [event for event, _ in pairs]
    raw = {event.raw[0].key: hit["_source"] for event, hit in pairs}
    rule.bind_raw(raw)
    matches = rule.consume(events)
    staged, held, released = {}, [], []
    sweep._record_playbook_batch(rule, matches, raw, None, staged, held, released)
    sweep._stage_put(list(staged.values()), raw, held, released)
    return matches


@pytest.mark.parametrize(("total", "records"), [(2*2**20, 4000), (64*2**20, 40000)])
def test_real_sweep_benign_ticket_flood_keeps_late_positive_and_actual_bytes(tmp_path, monkeypatch, total, records):
    rule = WindowsKerberoastDiversity()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir, disk_total=total, reserve=0))
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    sweep.budget.plan(70)
    for start in range(0, records, 100):
        assert not feed(sweep, rule, [native_ticket(n, f"u{n%50}", f"host/s{n%7}", n)
                                     for n in range(start, start+100)])
    attack = [native_ticket(90000+n, "late", f"mssql/db{n}", 9000+n) for n in range(10)]
    matches = feed(sweep, rule, attack)
    assert matches and rule.capped == 0 and not rule.limits
    assert sweep._event_stage().count() == 0
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= total
    [candidate] = sweep.repo.candidates("h1")
    assert len(candidate["event_ids"]) == 10
    assert set(candidate["event_ids"]) == {event.id for event, _ in attack}
    citations = sweep.repo.citation_events("h1", candidate["event_ids"])
    actual = {row["id"]: TypedEvent.model_validate(row["event"]) for row in citations}
    assert set(actual) == {event.id for event, _ in attack}
    assert {event.get("auth.service_name") for event in actual.values()} == {f"mssql/db{n}" for n in range(10)}
    assert {event.get("auth.target_account") for event in actual.values()} == {r"name:example.test\late@example.test"}
    expected_raw = {raw_id(hit["_index"], hit["_id"]): hit["_source"] for _, hit in attack}
    raw = sweep.repo.raw_records([identity for row in citations for identity in row["raw_ids"]])
    assert len(raw) == 10 and {row["id"]: row["source"] for row in raw} == expected_raw
    for event, _ in attack:
        assert actual[event.id].fields == event.fields
        assert actual[event.id].raw == event.raw
        assert actual[event.id].ts == event.ts
    assert not any("body not retrieved" in note for note in candidate["gate_results"]["_notes"])
    rule.release_state()
    sweep._event_stage().close()


def test_native_refs_survive_connection_reopen_and_duplicate_document_ids_across_indices():
    rule = WindowsKerberoastDiversity()
    pairs = [native_ticket(1, "alice", f"host/{n}", n, index) for n, index in enumerate(("logs-a", "logs-b"))]
    rule.consume([event for event, _ in pairs])
    spill = rule.rows.store()
    spill.flush()
    import sqlite3
    spill.db.close()
    spill.db = sqlite3.connect(spill.path)
    compact = rule.rows.compact([event.id for event, _ in pairs])
    assert len(compact) == 2
    assert {event.raw[0].target for event in compact} == {"logs-a", "logs-b"}
    assert compact[0].raw[0].native_id == compact[1].raw[0].native_id
    assert not rule.drain_staged()
    rule.release_state()


def test_native_missing_bodies_still_publish_and_fetch_checks_native_index():
    rule = WindowsKerberoastDiversity()
    pairs = [native_ticket(n, "alice", f"host/{n}", n) for n in range(10)]
    match = rule.consume([event for event, _ in pairs])[0]
    class Client:
        def search(self, index, body):
            wanted = body["query"]["bool"]["filter"][0]["ids"]["values"]
            return {"hits": {"hits": [hit for _, hit in pairs if hit["_id"] in wanted and hit["_index"] == index]}}
    WindowsCitationFetcher(Client()).hydrate(match)
    assert len(match.raw_copies) == 10
    assert not any(event.caveats for event in match.events)
    rule.release_state()


@pytest.mark.parametrize("shape", ["winlogbeat_7", "winlogbeat_8", "elastic_agent"])
def test_slow_native_daily_plus_hunt_span_and_midnight_breadth_fold_per_key(shape):
    records = [failure(day*96+n, offset=day*86400+n*800, shape=shape) for day in range(14) for n in range(96)]
    rule = WindowsPasswordSpray()
    matches = run(rule, [records[n:n+96] for n in range(0, len(records), 96)])
    broad = [match for match in matches if "hunt span" in match.claim]
    assert len(broad) == 2 and all("1344 distinct" in match.claim for match in broad)
    assert all(len(match.events) <= 100 for match in broad)
    assert all(any("central DCs" in note for note in match.notes) for match in broad)
    rule.release_state()
    # 120 accounts over six hours straddling midnight: neither ordinary UTC day reaches 100.
    records = [failure(n, offset=18*3600+n*180, shape=shape) for n in range(120)]
    rule = WindowsPasswordSpray()
    matches = run(rule, records)
    assert len([match for match in matches if "distinct target-account identities during" in match.claim]) == 2
    rule.release_state()


def test_brute_force_never_interns_per_record_ids():
    from romulus.detect.windows_auth_events import WindowsBruteForce
    rule = WindowsBruteForce()
    records = [failure(n, account="alice", offset=n*601) for n in range(100)]
    rule.consume(records)
    symbols = {row[0] for row in rule.rows.store().execute("SELECT value FROM windows_symbols")}
    assert not symbols.intersection(event.id for event in records)
    rule.release_state()


def test_native_burst_expiry_uses_timestamp_leading_index():
    rule = WindowsKerberoastDiversity()
    rule.consume([ticket(n, service="host/same") for n in range(20)])
    plan = rule.rows.store().execute(
        "EXPLAIN QUERY PLAN SELECT * FROM windows_rows WHERE ts<? LIMIT 256", (START.timestamp(),)).fetchall()
    assert any("windows_rows_expiry" in row[-1] and "SEARCH" in row[-1] for row in plan)
    rule.release_state()


def test_event_stage_enforces_own_budget_on_direct_writers_and_rolls_back(tmp_path):
    budget = StateBudget(tmp_path, disk_total=256*1024, reserve=0)
    budget.plan(2)
    stage = EventStage(tmp_path, budget=budget)
    event, hit = native_ticket(1, "alice", "host/one", 1)
    hit["_source"]["message"] = "x"*(1024*1024)
    stage.put([event], {event.raw[0].key: hit["_source"]})
    assert stage.refused == 1 and stage.refusal_reason and stage.count() == 1
    assert stage.load([event.id])[0].fields == event.fields
    assert "Citation body not retained" in str(stage.load([event.id])[0].caveats)
    assert sum(path.stat().st_size for path in Path(tmp_path).rglob("*") if path.is_file()) <= budget.disk_total
    assert stage.db.execute("PRAGMA max_page_count").fetchone()[0] * 4096 <= budget.disk_total
    stage.close()


def test_missing_witness_body_survives_real_sweep_report_and_agent_toolbox(tmp_path, monkeypatch):
    from romulus.agent.toolbox import Toolbox
    from romulus.report.manifest import build_manifest
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    rule = WindowsKerberoastDiversity()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": START.isoformat(), "end": (START+timedelta(days=1)).isoformat()},
                            "style": "broad", "original_input": {}, "normalizer": "windows", "policy": "test",
                            "model": {}, "romulus_version": "test", "targets": ["logs-windows-fixture"],
                            "pack": {"version": "test", "playbooks": [{"id": rule.id}]}}, "d", "test")
    sweep = sw.Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    # Cross-batch witnesses are never in the body stage; a failed re-read must not erase their finding.
    for n in range(10):
        feed(sweep, rule, [native_ticket(n, "alice", f"host/{n}", n)])
    candidate = repo.candidates("h1")[0]
    assert any("body not retrieved" in note for note in candidate["gate_results"]["_notes"])
    manifest = build_manifest(repo, "h1", "test")
    finding = next(item for item in manifest["findings"] if item["id"] == candidate["id"])
    assert any("body not retrieved" in note for note in finding["notes"])
    assert all(cite["native_id"] and cite["event_ts"] for cite in finding["citations"])
    toolbox = Toolbox(repo, "h1")
    toolbox.execute("list_findings", {"page": 1})
    view = toolbox.execute("get_finding", {"finding": "F1"})
    assert "body not retrieved" in str(view)
    aliases = view["data"]["finding"]["evidence"]
    evidence = toolbox.execute("get_evidence", {"evidence": aliases})
    assert evidence["counts"]["returned"] == 10
    assert "body not retrieved" in str(evidence)
    assert "native_id" in str(evidence)
    rule.release_state()
    sweep._event_stage().close()


def test_bursts_fold_across_buckets_with_bounded_witness_list_and_total_count():
    rule = WindowsKerberoastDiversity()
    records = [ticket(n, offset=n if n < 10 else n+600) for n in range(20)]
    matches = run(rule, records)
    assert len(matches) == 1 and len(matches[0].events) <= 11
    assert any("20 recorded witnesses" in note for note in matches[0].notes)
    rule.release_state()


def test_native_duplicate_document_ids_fetch_from_their_own_indices():
    rule = WindowsKerberoastDiversity()
    pairs = [native_ticket(n, "alice", f"host/{index}/{n}", n, index)
             for index in ("logs-a", "logs-b") for n in range(5)]
    match = rule.consume([event for event, _ in pairs])[0]
    class Client:
        def search(self, index, body):
            wanted = body["query"]["bool"]["filter"][0]["ids"]["values"]
            # A backend returning both indices must not overwrite the intended native reference.
            return {"hits": {"hits": [hit for _, hit in pairs if hit["_id"] in wanted]}}
    WindowsCitationFetcher(Client()).hydrate(match)
    assert len(match.raw_copies) == 10
    assert {event.raw[0].target for event in match.events} == {"logs-a", "logs-b"}
    assert not any(event.caveats for event in match.events)
    rule.release_state()


def test_real_sweep_strong_stage_refusal_is_named_and_never_bypasses_budget(tmp_path, monkeypatch):
    rule = WindowsKerberoastDiversity()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir, disk_total=2*2**20, reserve=0))
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    sweep.budget.force_full("injected stage byte allowance", lambda account: account.name == "event_stage")
    event, hit = native_ticket(1, "alice", "host/one", 1)
    sweep._stage_put([event], {event.raw[0].key: hit["_source"]})
    assert sweep._event_stage().count() == 1 and sweep._event_stage().refused == 1
    assert not rule.limits and "stage byte allowance" in sweep._event_stage().refusal_reason
    assert sweep._event_stage().load([event.id])[0].fields == event.fields
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= sweep.budget.disk_total
    sweep._event_stage().close()


def test_real_sweep_native_refs_are_durable_after_abrupt_process_exit(tmp_path):
    import json
    import sqlite3
    import subprocess
    import sys
    import textwrap
    script = textwrap.dedent("""
        import json, os, sys
        from datetime import timedelta
        from tests.test_windows_c_round3_storage import native_ticket, feed, START
        from tests.test_sweep import _repo
        from romulus.detect.bounded import StateBudget
        from romulus.detect.windows_auth_events import WindowsKerberoastDiversity
        from romulus.hunt import sweep as sw
        from romulus.sources.models import Window
        rule = WindowsKerberoastDiversity()
        sw.fresh_pack = lambda: [rule]
        sw.state_budget = lambda settings, stage_dir: StateBudget(stage_dir, disk_total=2*2**20, reserve=0)
        sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=sys.argv[1])
        feed(sweep, rule, [native_ticket(n, 'alice', f'host/{n}', n) for n in range(5)])
        print(json.dumps([str(rule.rows.store().path), str(sweep._event_stage().path)]), flush=True)
        os._exit(0)
    """)
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True,
                            check=True, timeout=30)
    refs_path, stage_path = json.loads(result.stdout)
    with sqlite3.connect(refs_path) as db:
        assert db.execute("SELECT COUNT(*) FROM windows_refs").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM windows_rows").fetchone()[0] == 5
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with sqlite3.connect(stage_path) as db:
        assert db.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 0
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= 2*2**20


def test_real_sweep_fresh_replay_reconstructs_native_ref_aggregation(tmp_path, monkeypatch):
    from tests.test_sweep import _complete
    pairs = [native_ticket(n, "alice", f"host/{n}", n) for n in range(10)]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [
        hit for event, hit in pairs if intent.window.start <= event.ts < intent.window.end]))
    rules = []
    def pack():
        rule = WindowsKerberoastDiversity()
        rules.append(rule)
        return [rule]
    monkeypatch.setattr(sw, "fresh_pack", pack)
    repo = _repo()
    window = Window(start=START, end=START+timedelta(seconds=20))
    first = Window(start=START, end=START+timedelta(seconds=5))
    second = Window(start=first.end, end=window.end)
    original = sw.Sweep(repo, None, "h1", window, {"logs-windows-fixture": None}, stage_dir=tmp_path)
    original.run_partition("logs-windows-fixture", None, [], first, est=5)
    assert not repo.candidates("h1")
    original.close_stage()
    resumed = sw.Sweep(repo, None, "h1", window, {"logs-windows-fixture": None}, stage_dir=tmp_path)
    # A fresh sweep can reconstruct compact state by re-reading already-evaluated source partitions.
    resumed.run_partition("logs-windows-fixture", None, [], first, est=5)
    resumed.run_partition("logs-windows-fixture", None, [], second, est=5)
    assert len(repo.candidates("h1")) == 1
    assert resumed._event_stage().count() == 0
    assert rules[-1].capped == 0 and not rules[-1].limits
    resumed.finalize()


def test_windows_auxiliary_databases_share_physical_ledger_and_byte_ceiling(tmp_path):
    from romulus.evidence.windows import RecordIdContinuity
    from romulus.evidence.windows_catalog import POWERSHELL_CHANNEL, POWERSHELL_PROVIDER
    from romulus.evidence.windows_reassembly import ScriptBlockAssembler
    budget = StateBudget(tmp_path, disk_total=512*1024, reserve=0)
    budget.plan(4)
    seen = budget.account("windows_seen")
    continuity_account = budget.account("windows_continuity")
    scripts_account = budget.account("windows_scripts")
    stage = EventStage(tmp_path, budget=budget, windows_account=seen)
    continuity = RecordIdContinuity(stage.directory, budget=budget, account=continuity_account)
    assembler = ScriptBlockAssembler(stage.directory, budget=budget, account=scripts_account)
    for n in range(12):
        logical = LogicalWindowsEvent(POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104, "dc01.example.test", n+1,
            (START+timedelta(seconds=n)).isoformat().replace("+00:00", "Z"),
            {"ScriptBlockId": f"00000000-0000-0000-0000-{n:012x}", "MessageNumber": "1", "MessageTotal": "2",
             "ScriptBlockText": "x"*32000})
        hit = windows_hit(logical, "winlogbeat_8")
        event = normalize_windows(hit)
        assembler.consume([event], {event.raw[0].key: hit["_source"]})
        stage.unique_windows([event])
        continuity.observe("logs-windows-fixture", [hit])
    assert assembler.refusal_reasons and not budget.broken
    assert all(("account", id(account)) in budget._physical for account in (seen, continuity_account, scripts_account))
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= budget.disk_total
    assert continuity._db.execute("PRAGMA journal_mode").fetchone()[0] == "memory"
    assert assembler.db.execute("PRAGMA journal_mode").fetchone()[0] == "memory"
    assert stage.windows_db.execute("PRAGMA journal_mode").fetchone()[0] == "memory"
    continuity.close()
    assembler.close()
    stage.close()
    budget.release_physical_account(continuity_account)
    budget.release_physical_account(scripts_account)
    assert budget.physical_used == 0
