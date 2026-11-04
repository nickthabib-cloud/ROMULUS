"""Native round-four regressions for latest witnesses and citation-independent publication."""
from datetime import timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.windows_auth_events import (
    WindowsBruteForce,
    WindowsExplicitCredentialFanout,
    WindowsKerberoastDiversity,
    WindowsPasswordSpray,
)
from romulus.hunt import sweep as sw
from romulus.sources.es import SourceError
from romulus.sources.models import Window
from tests.test_bounded_starvation import _Listed
from tests.test_sweep import _complete, _repo
from tests.test_windows_c_burst_review import START, failure, native_event, ticket
from tests.windows_process_support import run


def dns(n, name, *, pad=0):
    from romulus.evidence.normalize import normalize_hits
    from tests.throughput_fixture import Builder
    builder = Builder(73)
    builder.eve(START+timedelta(seconds=n), "dns", "10.0.0.5", 40000, "10.0.0.53", 53,
                proto="UDP", dns={"type": "query", "rrname": name, "rrtype": "A", "id": n})
    hit = builder.network[0]
    hit["_id"] = f"dns-{n}"
    hit["_source"]["message"] = "x"*pad
    events, _skips, errors = normalize_hits([hit])
    assert not errors and len(events) == 1
    return events[0], hit



@pytest.mark.parametrize("retrieve", [False, True])
@pytest.mark.parametrize("owner_overrun", [False, True])
def test_all_151_native_high_iocs_publish_after_body_owner_quota_with_local_citation_coverage(
        tmp_path, monkeypatch, retrieve, owner_overrun):
    class Control(_Listed):
        id = "test.retained_ioc"
        def consume(self, events):
            return super().consume([event for event in events if event.get("dns.question.name") == "control.c2.test"])
    class Targets(_Listed):
        def consume(self, events):
            return super().consume([event for event in events if event.get("dns.question.name") != "control.c2.test"])
    control, target = Control(), Targets()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [control, target])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir, disk_total=400000, reserve=0))
    pairs = [dns(0, "control.c2.test")] + [dns(n+1, f"b{n}.c2.test", pad=4000) for n in range(150)]
    pairs += [dns(152, "stage2.c2.test", pad=4000)]
    class Client:
        def search(self, index, body):
            if not retrieve:
                raise SourceError("source document rolled off")
            ids = body["query"]["bool"]["filter"][0]["ids"]["values"]
            return {"hits": {"hits": [hit for _, hit in pairs if hit["_index"] == index and hit["_id"] in ids]}}
    repo = _repo()
    sweep = sw.Sweep(repo, Client(), "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    if owner_overrun:
        account = sweep._stage_owner_accounts[target.id]
        assert account.strong
        sweep.budget.charge(account, sweep.budget.floor_of(account)+sweep.budget.pool+1)
        assert account.used > sweep.budget.floor_of(account)+sweep.budget.pool
        assert sweep.budget.physical_used < sweep.budget.disk_total
    # Separate source partitions ensure the control's retained body predates the noisy owner's refusal.
    for subset in (pairs[:1], pairs[1:-1], pairs[-1:]):
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract, subset=subset: _complete(intent, [hit for _, hit in subset]))
        window = Window(start=subset[0][0].ts, end=subset[-1][0].ts+timedelta(seconds=1))
        sweep.run_partition("logs-windows-fixture", None, [], window, est=len(subset))
    assert sweep._event_stage().refused > 0
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= 400000
    sweep.finalize()
    records = repo.candidates("h1")
    targets = [row for row in records if row["rule_id"] == target.id]
    assert len(targets) == 151 and all(row["lane"] == "high" for row in targets)
    assert any("stage2.c2.test" in row["claim"] for row in targets)
    [retained] = [row for row in records if row["rule_id"] == control.id]
    assert "body not retrieved" not in retained["claim"]
    missing = [row for row in targets if "body not retrieved" in row["claim"]]
    assert bool(missing) is (not retrieve)
    assert all("Citation coverage is partial for this finding" in row["claim"] for row in missing)
    assert all(not any("finalize stopped" in reason for reason in rule.limit_reasons()) for rule in (control, target))
    for row in missing:
        citations = repo.citation_events("h1", row["event_ids"])
        assert citations and all(item["event"]["raw"] and item["ts"] and item["event"]["fields"] for item in citations)


@pytest.mark.parametrize("kind", ["kerberos", "brute", "explicit", "spray", "source_less"])
def test_later_native_qualifying_window_revises_same_key_and_cites_its_own_members(kind):
    if kind == "kerberos":
        rule = WindowsKerberoastDiversity()
        old = [ticket(n, service=f"host/normal{n}") for n in range(10)]
        latest = [ticket(1000+n, service=f"mssql/latest{n}", offset=7*86400+n) for n in range(60)]
    elif kind == "brute":
        rule = WindowsBruteForce()
        old = [failure(n, account="alice") for n in range(20)]
        latest = [failure(1000+n, account="alice", offset=7*86400+n) for n in range(60)]
    elif kind == "explicit":
        rule = WindowsExplicitCredentialFanout()
        def explicit(n, offset):
            return native_event(4648, {"SubjectUserSid": "S-1-5-21-1-2-3-1100", "TargetUserName": "alice",
                                      "TargetDomainName": "EXAMPLE", "IpAddress": "203.0.113.5", "Status": "0x0",
                                      "TargetServerName": f"server{n}"}, offset=offset)
        old = [explicit(n, n) for n in range(5)]
        latest = [explicit(1000+n, 7*86400+n) for n in range(15)]
    else:
        rule = WindowsPasswordSpray()
        source = None if kind == "source_less" else "203.0.113.5"
        old = [failure(n, source=source, account=f"staff{n}") for n in range(20)]
        latest = [failure(1000+n, source=source, account=f"latest{n}", offset=9*86400+n) for n in range(60)]
    matches = run(rule, [old, latest])
    bursts = [match for match in matches if "First qualifying window" in match.claim]
    assert len(bursts) == (2 if kind in {"spray", "source_less"} else 1)
    latest_ids = {event.id for event in latest}
    for match in bursts:
        assert {event.id for event in match.events} <= latest_ids | {event.id for event in old}
        assert {event.id for event in old} <= {event.id for event in match.events}
        assert {event.id for event in latest[-rule.threshold:]} <= {event.id for event in match.events}
        assert len(match.events) <= 2*rule.threshold and match.revision_reason
        assert old[0].ts.isoformat() in match.claim and latest[-1].ts.isoformat() in match.claim
        assert "qualifying windows" in match.claim and "2 episodes" in match.claim
    rule.release_state()


def test_daily_native_final_revision_uses_latest_accounts_instead_of_first_hundred():
    rule = WindowsPasswordSpray()
    old = [failure(n, source=None, account=f"staff{n}", offset=n*500) for n in range(150)]
    latest = [failure(10000+n, source=None, account=f"victim{n}", offset=9*86400+n*10) for n in range(300)]
    matches = run(rule, [old, latest])
    breadth = [match for match in matches if "distinct-account witnesses are cited" in match.claim]
    assert len(breadth) == 2 and all(len(match.events) == 100 for match in breadth)
    assert all({event.id for event in match.events} <= {event.id for event in latest} for match in breadth)
    assert all("450 distinct" in match.claim for match in breadth)
    rule.release_state()


def test_compact_publication_uses_verified_body_retained_by_an_earlier_immediate_finding(tmp_path, monkeypatch):
    from dataclasses import replace

    from romulus.hunt.publish import publish_match
    rule = _Listed()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    repo = _repo()
    sweep = sw.Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    sweep.budget.force_full("force standalone positive", lambda account: account.name.startswith(rule.id+":"))
    event, hit = dns(1, "retained.c2.test")
    [immediate] = rule.consume([event])
    assert publish_match(repo, "h1", rule, immediate, None, {event.raw[0].key: hit["_source"]})
    sweep.budget.force_full("body cache quota", lambda account: account.name.startswith("event_stage"))
    sweep._stage_put([event], {})
    compact = replace(immediate, events=sweep._event_stage().load([event.id]), group_key=immediate.group_key+":compact")
    [row] = [publish_match(repo, "h1", rule, compact, None, {})]
    assert row and "body not retrieved" not in row["claim"]
    assert not any("body not retained" in note.lower() for item in compact.events for note in item.caveats)
    sweep.close_stage()


def test_one_actual_compact_write_refusal_preserves_other_same_rule_ioc_groups(tmp_path, monkeypatch):
    import sqlite3

    from romulus.hunt import stage as stage_mod

    rule = _Listed()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir:
                        StateBudget(stage_dir, disk_total=400000, reserve=0))
    repo = _repo()
    sweep = sw.Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    pairs = [dns(n, f"group{n}.c2.test", pad=4000) for n in range(151)]
    refused_id = pairs[70][0].id
    real_compact = stage_mod.compact_event

    def compact(event):
        if event.id == refused_id:
            raise sqlite3.OperationalError("database or disk is full")
        return real_compact(event)

    monkeypatch.setattr(stage_mod, "compact_event", compact)
    for subset in (pairs[:1], pairs[1:150], pairs[150:]):
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract, subset=subset:
                            _complete(intent, [hit for _, hit in subset]))
        sweep.run_partition("logs-native-eve", None, [], Window(start=subset[0][0].ts,
                            end=subset[-1][0].ts+timedelta(seconds=1)), est=len(subset))
    assert sweep._event_stage().count() == 150
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= 400000
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 151 and all(row["lane"] == "high" for row in candidates)
    [uncited] = [row for row in candidates if not row["event_ids"]]
    assert "no citation could be retained" in uncited["claim"] and "group70.c2.test" in uncited["claim"]
    assert any("group70.c2.test" in reason for reason in rule.limit_reasons())
    assert {event.id for event, _ in pairs}-{refused_id} == {
        identity for row in candidates for identity in row["event_ids"]}
    assert "citation_reference" in rule.limits
    assert not any("finalize stopped" in reason for reason in rule.limit_reasons())


def test_missing_native_join_subject_preserves_the_other_process_network_group(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from romulus.detect.correlation import ProcessNetworkLink
    from romulus.evidence.normalize import normalize_hits
    from tests.test_network_correlation import T0, audit_hit, flow, sockaddr, syscall

    rule = ProcessNetworkLink()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    later = datetime.fromtimestamp(T0+3600, UTC)
    records = [audit_hit("bad-s", syscall(), host="bad"), audit_hit("bad-k", sockaddr(), host="bad"),
               flow("bad-f"), audit_hit("good-s", syscall(serial=501, t0=T0+3600), host="good"),
               audit_hit("good-k", sockaddr(serial=501, t0=T0+3600), host="good"),
               flow("good-f", start=later.isoformat(), end=(later+timedelta(minutes=30)).isoformat())]
    events, _skips, errors = normalize_hits(records)
    assert not errors
    refused = {event.id for event in events if event.host == "bad"}
    repo = _repo()
    window = Window(start=datetime.fromtimestamp(T0, UTC), end=later+timedelta(hours=1))
    sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, records))
    sweep.run_partition("logs-native-audit-and-eve", None, [], window, est=len(records))
    stage = sweep._event_stage()
    load = stage.load
    monkeypatch.setattr(stage, "load", lambda ids: [event for event in load(ids) if event.id not in refused])
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 2
    [uncited] = [row for row in candidates if not row["event_ids"]]
    assert "bad" in uncited["claim"] and "no citation could be retained" in uncited["claim"]
    [candidate] = [row for row in candidates if row["event_ids"]]
    assert candidate["rule_id"] == rule.id and "good" in candidate["claim"]
    assert "citation_reference" in rule.limits
    assert not any("finalize stopped" in reason for reason in rule.limit_reasons())


@pytest.mark.parametrize("missing", [0, 2])
@pytest.mark.parametrize("kind", ["root_files", "unbacked"])
def test_missing_native_host_subject_preserves_other_file_groups(tmp_path, monkeypatch, kind, missing):
    from datetime import UTC, datetime

    from romulus.detect.host import UnbackedExecutable
    from romulus.detect.kernel_files import RootExecNonRootModifiableFile
    from romulus.evidence.normalize import normalize_hits
    from tests.test_kernel_records import cwd, execve, hit, path, syscall

    rule = RootExecNonRootModifiableFile() if kind == "root_files" else UnbackedExecutable()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    records = []
    for n in range(3):
        executable = f"/opt/app/run{n}" if kind == "root_files" else f"/memfd:run{n} (deleted)"
        serial = 700+n
        lines = [execve(serial, executable), syscall(serial, 59, "execve", exe=executable),
                 path(serial, 0, executable, "NORMAL", mode="0100755", ouid="33", ogid="33"), cwd(serial)]
        records += [hit(f"file-{n}-{i}", line) for i, line in enumerate(lines)]
    events, _skips, errors = normalize_hits(records)
    assert not errors and len(events) == 3
    refused_id = events[missing].id
    repo = _repo()
    start = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
    window = Window(start=start, end=start+timedelta(hours=1))
    sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, records))
    sweep.run_partition("romulus-host-x", None, [], window, est=len(records))
    stage = sweep._event_stage()
    load = stage.load
    monkeypatch.setattr(stage, "load", lambda ids: [event for event in load(ids) if event.id != refused_id])
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 3
    [uncited] = [row for row in candidates if not row["event_ids"]]
    assert "no citation could be retained" in uncited["claim"] and f"run{missing}" in uncited["claim"]
    assert {event.id for event in events}-{refused_id} == {
        identity for row in candidates for identity in row["event_ids"]}
    assert "citation_reference" in rule.limits
    assert not any("finalize stopped" in reason for reason in rule.limit_reasons())


def test_native_dns_replaced_partition_holds_do_not_spend_the_final_witness_budget(tmp_path, monkeypatch):
    import hashlib

    from romulus.detect.dns import DnsTunnelShape

    rule = DnsTunnelShape()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir:
                        StateBudget(stage_dir, disk_total=256000, reserve=0))
    pairs = [dns(n, hashlib.sha256(str(n).encode()).hexdigest()[:60]+".tunnel.test", pad=4000) for n in range(400)]
    repo = _repo()
    window = Window(start=START, end=START+timedelta(hours=1))
    sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path)
    stage = sweep._event_stage()
    assert stage.db.execute("SELECT rootpage FROM sqlite_master WHERE name='citation_owner'").fetchone()[0] > 0
    assert sweep._stage_owner_accounts[rule.id].used == 0
    shared_bytes = stage._size + (stage._windows_size if stage.windows_account is stage.account else 0)
    assert sweep.budget._physical[("account", id(stage.account))][0] == shared_bytes
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [hit for _, hit in pairs]))
    sweep.run_partition("logs-native-eve", None, [], window, est=len(pairs))
    assert sweep._event_stage().count() <= 30
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= 256000
    sweep.finalize()
    [candidate] = repo.candidates("h1")
    assert candidate["rule_id"] == rule.id and candidate["lane"] == "lead"
    assert "400" in candidate["claim"] and "tunnel.test" in candidate["claim"]
    assert not rule.limits


def test_native_cache_repacking_rolls_back_deleted_events_and_all_id_relations(tmp_path, monkeypatch):
    import sqlite3

    rule = _Listed()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    event, hit = dns(1, "rollback.c2.test", pad=1000)
    repo = _repo()
    window = Window(start=START, end=START+timedelta(hours=1))
    sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [hit]))
    sweep.run_partition("logs-native-eve", None, [], window, est=1)
    sweep._stage_put([], {}, [(rule.id, event)])
    stage = sweep._event_stage()
    tables = ("event", "event_raw", "hold", "citation_owner", "raw")
    before = {table: stage.db.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
    bookkeeping = (stage._text_rows, dict(stage._body_revisions), dict(stage._raw_revisions))
    connection = stage.db

    class FailingInsert:
        def __getattr__(self, name):
            return getattr(connection, name)
        def __enter__(self):
            return connection.__enter__()
        def __exit__(self, *args):
            return connection.__exit__(*args)
        def executemany(self, sql, rows):
            if sql == "INSERT INTO event(id,body,kept,reclaim,seq) VALUES(?,?,?,?,?)":
                raise sqlite3.OperationalError("database or disk is full")
            return connection.executemany(sql, rows)

    stage.db = FailingInsert()
    with pytest.raises(sqlite3.OperationalError, match="full"):
        stage._compact_cache([event], (sweep._stage_owner_accounts[rule.id],))
    assert before == {table: connection.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
    assert bookkeeping == (stage._text_rows, dict(stage._body_revisions), dict(stage._raw_revisions))
    assert not stage._cache_passes
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert stage.raw_sources([event])[event.raw[0].key] == hit["_source"]
    stage.db = connection
    sweep.close_stage()


def test_native_body_quota_history_work_is_linear_and_all_highs_survive(tmp_path, monkeypatch):
    results = []
    for seed, later in ((100, 200), (200, 400)):
        rule = _Listed()
        monkeypatch.setattr(sw, "fresh_pack", lambda rule=rule: [rule])
        monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir:
                            StateBudget(stage_dir, disk_total=64*2**20, reserve=0))
        repo = _repo()
        window = Window(start=START, end=START+timedelta(hours=1))
        sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path/str(seed))
        stage = sweep._event_stage()

        def feed(start, count, sweep=sweep, window=window):
            pairs = [dns(n, f"linear{n}.c2.test") for n in range(start, start+count)]
            monkeypatch.setattr(sw, "execute", lambda client, intent, contract:
                                _complete(intent, [hit for _, hit in pairs]))
            sweep.run_partition("logs-native-eve", None, [], window, est=count)

        feed(0, seed)
        owner = sweep._stage_owner_accounts[rule.id]
        sweep.budget.force_full("body quota probe", lambda account, owner=owner: account is owner)
        trace = []
        stage.db.set_trace_callback(trace.append)
        for start in range(seed, seed+later, 50):
            feed(start, min(50, seed+later-start))
            assert stage._text_rows == 0
        stage.db.set_trace_callback(None)
        owner_queries = [sql for sql in trace if sql.startswith("SELECT c.id FROM citation_owner")]
        text_queries = [sql for sql in trace if sql.startswith("SELECT id,body,kept,reclaim,seq FROM event")]
        assert len(owner_queries) == 1 and len(text_queries) == 1
        # The only history chunk is the seeded text state, rather than every prior compact id each batch.
        history_ids = text_queries[0].split("WHERE id IN (", 1)[1].split(") AND", 1)[0].split(",")
        assert len(history_ids) == seed
        assert sum(path.stat().st_size for path in (tmp_path/str(seed)).rglob("*") if path.is_file()) <= 64*2**20
        sweep.finalize()
        candidates = repo.candidates("h1")
        assert len(candidates) == seed+later and all(row["lane"] == "high" for row in candidates)
        results.append(len(history_ids))
    assert results == [100, 200]


def test_native_cache_revisions_bound_contexts_and_reopen_shared_owner_truth(tmp_path, monkeypatch):
    import itertools
    import sqlite3

    rules = [type(f"Listed{n}", (_Listed,), {"id": f"test.listed{n}"})() for n in range(6)]
    monkeypatch.setattr(sw, "fresh_pack", lambda: rules)
    repo = _repo()
    window = Window(start=START, end=START+timedelta(hours=1))
    sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path)
    stage = sweep._event_stage()
    owners = tuple(sweep._stage_owner_accounts[rule.id] for rule in rules)
    trace = []
    stage.db.set_trace_callback(trace.append)

    def feed(n):
        event, hit = dns(n, f"shared{n}.c2.test")
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [hit]))
        sweep.run_partition("logs-native-eve", None, [], window, est=1)
        return event

    first = feed(1)
    contexts = [subset for size in range(1, len(owners)) for subset in itertools.combinations(owners, size)]
    for context in contexts:
        stage._compact_cache([], context)
        assert stage._text_rows == 1       # a shared body is not reclaimed without all of its owners
        assert len(stage._cache_passes) <= 4*(len(stage.owner_accounts)+1)
    unchanged_queries = sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in trace)
    for _ in range(5):
        stage._compact_cache([], contexts[-1])
    assert stage._text_rows == 1
    assert sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in trace) == unchanged_queries
    stage._compact_cache([], owners)
    assert stage._text_rows == 0 and stage.load([first.id])[0].fields == first.fields
    queries = sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in trace)
    for context in contexts:
        stage._compact_cache([], context)
    assert sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in trace) == queries

    second = feed(2)
    assert stage._text_rows == 1
    stage._compact_cache([], owners)
    assert stage._text_rows == 0 and stage.load([second.id])[0].fields == second.fields
    assert sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in trace) == queries+1

    third = feed(3)
    stage.db.close()
    stage.db = sqlite3.connect(stage.path)
    stage.db.execute("PRAGMA journal_mode=MEMORY")
    stage.db.execute("PRAGMA synchronous=OFF")
    cold_trace = []
    stage.db.set_trace_callback(cold_trace.append)
    stage._compact_cache([], owners)
    stage._compact_cache([], owners)
    assert sum(sql.startswith("SELECT COUNT(*) FROM event WHERE typeof(body)") for sql in cold_trace) == 1
    assert stage._text_rows == 0 and stage.load([third.id])[0].fields == third.fields
    assert len(stage._body_revisions) <= len(owners) and len(stage._raw_revisions) <= len(owners)
    stage._compact_cache([], owners, drop_raw=True)
    raw_queries = sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in cold_trace)
    assert not stage._raw_table
    stage._compact_cache([], owners, drop_raw=True)
    assert sum(sql.startswith("SELECT c.id FROM citation_owner") for sql in cold_trace) == raw_queries
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 18 and all(row["lane"] == "high" for row in candidates)


@pytest.mark.parametrize("relax", ["compact", "release"])
def test_native_shared_raw_pin_relaxation_invalidates_the_other_owner(tmp_path, monkeypatch, relax):
    from datetime import UTC, datetime

    from romulus.detect.base import Playbook
    from romulus.evidence.normalize import normalize_hits
    from tests.test_kernel_records import cwd, group, path, syscall

    class Owner(Playbook):
        staged = True
        kind = "aggregate"
        families = ("file_change",)
        def __init__(self, side, held):
            super().__init__()
            self.id, self.side, self.held = "test."+side, side, held
            self.pending, self.holds = [], []
        def consume(self, events):
            self.pending.extend(event for event in events if event.get("file.change") == self.side)
            return []
        def drain_staged(self):
            events, self.pending = self.pending, []
            self.holds = [event.id for event in events] if self.held else []
            return events
        def drain_bounds(self):
            return self.holds, []

    records = group(syscall(30, 82, "rename", exe="/usr/bin/dpkg", comm="dpkg"),
                    path(30, 0, "/etc/cron.d/", "PARENT"), path(30, 1, "/etc/cron.d/", "PARENT"),
                    path(30, 2, "/etc/cron.d/job.dpkg-new", "DELETE", inode="300"),
                    path(30, 3, "/etc/cron.d/job", "CREATE", inode="300"), cwd(30))
    events, _skips, errors = normalize_hits(records)
    assert not errors and len(events) == 2
    source = next(event for event in events if event.get("file.change") == "rename_source")
    target = next(event for event in events if event.get("file.change") == "rename_target")
    [shared] = [ref.key for ref in source.raw if ref.native_id == "r0"]
    assert shared in {ref.key for ref in target.raw}
    a, b = Owner("rename_source", False), Owner("rename_target", True)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [a, b])
    start = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
    window = Window(start=start, end=start+timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, "h1", window, {}, stage_dir=tmp_path)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, records))
    sweep.run_partition("romulus-host-x", None, [], window, est=len(records))
    stage = sweep._event_stage()
    aa, ba = (sweep._stage_owner_accounts[rule.id] for rule in (a, b))
    stage._compact_cache([], (aa,))
    stage._compact_cache([], (aa,), drop_raw=True)
    assert shared in stage.raw_sources([source])   # the other typed view still pins this native body
    before = stage._raw_revisions[stage._owner_number(aa.name)]
    if relax == "compact":
        stage._compact_cache([], (ba,))
        assert stage.load([target.id])[0].fields == target.fields
    else:
        stage.release(b.id, [target.id])
        assert not stage.load([target.id])
    assert stage._raw_revisions[stage._owner_number(aa.name)] > before
    stage._compact_cache([], (aa,), drop_raw=True)
    assert shared not in stage.raw_sources([source])
    [retained] = stage.load([source.id])
    assert retained.fields == source.fields and retained.raw == source.raw and retained.ts == source.ts
    assert stage.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    sweep.close_stage()
