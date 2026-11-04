"""Schema allocation pressure retains native evidence and reaches Sweep's partial-state guard."""
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import SpillList, StateBudget, StateExhausted
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from tests.test_sweep import _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

START = datetime(2026, 1, 2, 3, tzinfo=UTC)


class _NativeDnsList(Playbook):
    id = "test.native_dns_list"
    title = "Native DNS storage witness"
    kind = "aggregate"
    families = ("dns_lookup",)
    state_slice = "strong"

    def __init__(self):
        super().__init__()
        self.records = SpillList(self, "native_dns_records", hot=0)

    def consume(self, events):
        for event in self.applicable(events):
            assert self.records.append(event)
        self.records.trim()
        return [Match(self.id, f"Recorded DNS question {event.get('dns.question.name')}",
                      "network_observation", [event], [pf(event, "dns.question.name")],
                      event.ts, "high", "high", "high") for event in self.records]


class _SchemaPressure:
    """Constrain only this list's CREATE; every other operation uses the real SQLite connection."""
    def __init__(self, connection, error=None):
        self.connection = connection
        self.error = error

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, sql, *args):
        if sql.startswith("CREATE TABLE IF NOT EXISTS native_dns_records "):
            if self.error is not None:
                raise sqlite3.OperationalError(self.error)
            pages = self.connection.execute("PRAGMA page_count").fetchone()[0]
            self.connection.execute(f"PRAGMA max_page_count = {max(1, pages)}")
        return self.connection.execute(sql, *args)


def _native():
    hit = windows_hit(LogicalWindowsEvent("Microsoft-Windows-Sysmon/Operational", SYSMON, 22,
        "ws01.example.test", 500, START.isoformat().replace("+00:00", "Z"),
        {"Image": r"C:\Program Files\Example\client.exe", "ProcessId": "1000",
         "QueryName": "storage-witness.example.test", "QueryStatus": "0", "QueryResults": "203.0.113.8"}),
        "winlogbeat_8")
    return normalize_windows(hit), hit


def test_schema_full_keeps_native_buffer_and_publishes_cited_high_on_partial_sweep(monkeypatch, tmp_path):
    rule = _NativeDnsList()
    budget = StateBudget(tmp_path, disk_total=2**30, reserve=0)
    rule.budget, rule.spill_dir = budget, tmp_path
    spill = rule.spill()
    spill.db = _SchemaPressure(spill.db)
    event, hit = _native()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, directory: budget)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="native", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=1, total_relation="eq", returned=1, records=[hit]))
    repo = _repo()
    window = Window(start=START, end=START+timedelta(minutes=5))
    sweep = sw.Sweep(repo, object(), "h1", window, {hit["_index"]: None}, stage_dir=tmp_path)
    try:
        sweep.run_partition(hit["_index"], None, [], window, est=1)
        assert list(rule.records) == [event]
        assert not rule.records._ready and rule.records.on_disk == rule.records.disk_bytes == 0
        assert rule.records.account().used == 0
        assert budget._physical[("spill", id(spill))][0] == spill._size == 0
        with pytest.raises(StateExhausted):
            rule.records.trim(0)
        assert list(rule.records) == [event]
        sweep.finalize()
        [candidate] = repo.candidates("h1")
        assert candidate["lane"] == "high" and candidate["event_ids"] == [event.id]
        [citation] = repo.citation_events("h1", candidate["event_ids"])
        [raw] = repo.raw_records(citation["raw_ids"])
        assert raw["source"] == hit["_source"]
        [cell] = [cell for cell in repo.rule_cells("h1") if cell["partition"] == "window"]
        assert cell["state"] == "match_on_partial"
        assert any("detector spill reached its hunt byte allowance" in reason for reason in cell["detail"]["reasons"])
    finally:
        sweep.close_stage()
        repo.engine.dispose()


def test_schema_errors_other_than_capacity_are_not_hidden_and_keep_buffer(tmp_path):
    rule = _NativeDnsList()
    rule.spill_dir = tmp_path
    event, _ = _native()
    rule.records.append(event)
    spill = rule.spill()
    spill.db = _SchemaPressure(spill.db, "syntax error near native_dns_records")
    try:
        with pytest.raises(sqlite3.OperationalError, match="syntax error"):
            rule.records.trim()
        assert list(rule.records) == [event] and not rule.records._ready
        assert not rule.limits and not rule.state_budget().broken
    finally:
        rule.close_spill()
