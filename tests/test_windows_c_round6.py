"""Source faults and physical storage limits through native consume and publication."""
from datetime import timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect import bounded
from romulus.detect.bounded import KeyedStore, StateBudget
from romulus.detect.windows_auth_events import WindowsBruteForce
from romulus.hunt.publish import SourceCitationFetcher, WindowsCitationFetcher, publish_match
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, SearchIntent, Window
from romulus.sources.profile import contract_from_types
from tests.test_bounded_budget import _owner
from tests.test_sweep import _repo
from tests.test_windows_c_burst_review import START, failure
from tests.test_windows_c_round4 import dns
from tests.test_windows_c_round5 import _feed, _native_sweep


def html_client(status=200):
    return ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(
        lambda request: httpx.Response(status, headers={"content-type": "text/html"},
                                       text="<html>Sign in</html>")))


@pytest.mark.parametrize("status", [200, 302])
def test_nonjson_citation_response_keeps_every_native_positive(tmp_path, monkeypatch, status):
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(1, "first.c2.test"), dns(2, "second.c2.test")]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    stage._compact_cache([pairs[0][0]], (sweep._stage_owner_accounts[rule.id],), drop_raw=True)
    rule.citation_fetcher = SourceCitationFetcher(html_client(status))
    try:
        sweep.finalize()
        rows = sweep.repo.candidates("h1")
        assert len(rows) == 2 and all(row["lane"] == "high" for row in rows)
        assert all("non-JSON response" in row["claim"] and "partial" in row["claim"] for row in rows)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("shape", ["mismatch", "unidentified", "long", "rare", "rare_two", "burst", "packaged"])
@pytest.mark.parametrize("uncited_first", [True, False])
def test_cited_uncited_native_resume_keeps_one_identity(tmp_path, monkeypatch, shape, uncited_first):
    from romulus.detect.flows import LongUnidentifiedSession, ProtocolPortMismatch
    from romulus.detect.host import WebServiceSpawnsInterpreter
    from romulus.hunt import sweep as sw
    from tests.test_flow_rules import T0, ark, eve
    from tests.test_kernel_records import cwd, execve, hit, syscall
    from tests.test_sweep import _complete
    if shape in {"mismatch", "unidentified", "long"}:
        cls = LongUnidentifiedSession if shape == "long" else ProtocolPortMismatch
        hits = ([ark("long", dst="203.0.113.50", dport=2222, seconds=10800, c2s=4000, s2c=9000, pkts_s=12)]
                if shape == "long" else [eve("flow", dst="203.0.113.50", dport=443,
                   app_proto="ssh" if shape == "mismatch" else None, c2s=4000, s2c=9000, pkts_s=12)])
    else:
        cls, hits = WebServiceSpawnsInterpreter, []
        for n in range(8 if shape == "burst" else 2 if shape == "rare_two" else 1):
            serial = 900+n
            command = "/usr/lib/example/helper.py" if shape == "packaged" else "/opt/example/helper.py"
            lines = [execve(serial, "/usr/bin/python3", command),
                     syscall(serial, 59, "execve", uid="33", exe="/usr/bin/python3"), cwd(serial)]
            hits.extend(hit(f"web-{n}-{i}", line) for i, line in enumerate(lines))
    repo = _repo()
    seen = []
    for pass_number, uncited in enumerate((uncited_first, not uncited_first)):
        rule = cls()
        monkeypatch.setattr(sw, "fresh_pack", lambda rule=rule: [rule])
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
        window = Window(start=T0, end=START+timedelta(days=1))
        sweep = sw.Sweep(repo, None, "h1", window, {}, stage_dir=tmp_path/str(pass_number))
        try:
            sweep.run_partition(hits[0]["_index"], None, [], window, est=len(hits))
            if uncited:
                monkeypatch.setattr(sweep._event_stage(), "load", lambda ids: [])
            sweep.finalize()
            rows = repo.candidates("h1")
            assert len(rows) == (2 if shape == "rare_two" else 1)
            seen.append(sorted((row["id"], row["group_key"]) for row in rows))
        finally:
            sweep.close_stage()
    assert seen[0] == seen[1]


def test_uncited_native_beacon_has_real_record_time(tmp_path, monkeypatch):
    from romulus.detect.sessions import Beaconing
    from romulus.hunt import sweep as sw
    from tests.test_flow_rules import T0, ark
    from tests.test_sweep import _complete
    rule = Beaconing()
    hits = [ark(f"periodic-{n}", dst="203.0.113.50", dport=4444, start=T0+timedelta(minutes=n),
                sport=40000+n) for n in range(40)]
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
    window = Window(start=T0, end=T0+timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, "h1", window, {}, stage_dir=tmp_path)
    try:
        sweep.run_partition(hits[0]["_index"], None, [], window, est=len(hits))
        monkeypatch.setattr(sweep._event_stage(), "load", lambda ids: [])
        sweep.finalize()
        [row] = sweep.repo.candidates("h1")
        assert row["ts"].year == 2024
        assert window.start.replace(tzinfo=None) <= row["ts"] < window.end.replace(tzinfo=None)
    finally:
        sweep.close_stage()


def test_partial_rare_runs_cite_only_their_own_surviving_record(tmp_path, monkeypatch):
    from romulus.detect.host import WebServiceSpawnsInterpreter
    from romulus.hunt import sweep as sw
    from tests.test_kernel_records import cwd, execve, hit, syscall
    from tests.test_sweep import _complete
    rule, hits = WebServiceSpawnsInterpreter(), []
    for n in range(2):
        serial = 990+n
        lines = [execve(serial, "/usr/bin/python3", "/opt/example/helper.py"),
                 syscall(serial, 59, "execve", uid="33", exe="/usr/bin/python3"), cwd(serial)]
        hits.extend(hit(f"partial-{n}-{i}", line) for i, line in enumerate(lines))
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    try:
        sweep.run_partition(hits[0]["_index"], None, [], sweep.window, est=len(hits))
        stage = sweep._event_stage()
        original = stage.load
        [state] = [state for _key, state in rule.shapes.items()]
        ids = state[1].ids()
        assert len(ids) == 2
        survivor = ids[0]
        monkeypatch.setattr(stage, "load", lambda wanted: original([identity for identity in wanted if identity == survivor]))
        sweep.finalize()
        rows = sweep.repo.candidates("h1")
        assert len(rows) == 2 and len({row["id"] for row in rows}) == 2
        assert sorted(len(row["event_ids"]) for row in rows) == [0, 1]
        [cited] = [row for row in rows if row["event_ids"]]
        assert cited["event_ids"] == [survivor]
        assert "no citation could be retained" not in str(cited)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("reverse", [False, True])
def test_uncited_native_port_scan_preserves_computed_lane_and_reverse_raise(tmp_path, monkeypatch, reverse):
    from romulus.detect.network import PortScan
    from romulus.hunt import sweep as sw
    from tests.test_flow_rules import T0, eve
    from tests.test_sweep import _complete
    rule = PortScan()
    hits = [eve(f"answer-{n}", src="10.0.0.9", sport=53, dst="10.0.0.66", dport=40000+n,
                start=T0+timedelta(seconds=2)) for n in range(40)]
    if reverse:
        hits += [eve(f"probe-{n}", src="10.0.0.66", sport=40000+n, dst="10.0.0.9", dport=100+n,
                     start=T0) for n in range(40)]
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
    window = Window(start=T0, end=T0+timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, "h1", window, {}, stage_dir=tmp_path)
    try:
        sweep.run_partition(hits[0]["_index"], None, [], window, est=len(hits))
        monkeypatch.setattr(sweep._event_stage(), "load", lambda ids: [])
        sweep.finalize()
        [row] = [r for r in sweep.repo.candidates("h1") if r["group_key"] == "10.0.0.9|10.0.0.66"]
        assert row["lane"] == ("lead" if reverse else "context")
        if reverse:
            assert "opposite direction" in row["claim"].lower()
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("kind", ["raw", "aggregate", "histogram"])
def test_nonjson_query_response_is_a_named_incomplete_outcome(kind):
    intent = SearchIntent(target="logs", kind=kind, group_by=["host.name"] if kind == "aggregate" else [],
                          window=Window(start=START, end=START+timedelta(hours=1)))
    contract = contract_from_types("logs", {"@timestamp": "date", "host.name": "keyword"})
    outcome = execute(html_client(), intent, contract)
    assert outcome.completeness != Completeness.complete
    assert outcome.reasons == ["source_error"] and "non-JSON response" in outcome.error


def test_nonjson_auth_hydration_at_consume_keeps_computed_burst():
    rule, repo = WindowsBruteForce(), _repo()
    rule.citation_fetcher = WindowsCitationFetcher(html_client())
    try:
        matches = rule.consume([failure(n, account="service") for n in range(25)])
        assert matches
        for match in matches:
            publish_match(repo, "h1", rule, match, None, {})
        rows = repo.candidates("h1")
        assert rows and all("non-JSON response" in row["claim"] for row in rows)
    finally:
        rule.release_state()


def test_store_admits_past_legacy_per_store_cap_with_physical_room(tmp_path, monkeypatch):
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1024)
    budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    owner = _owner(tmp_path, budget, "past_legacy_cap")
    store = KeyedStore(owner, "records", hot=0)
    try:
        for n in range(20):
            assert store.put(str(n), bytes([n])*2048)
            store.trim()
        assert len(store) == 20 and not owner.limits
        assert budget.physical_used < budget.disk_total
    finally:
        owner.close_spill()


def test_native_stage_owner_metadata_is_interned_and_survives_connection_reopen(tmp_path, monkeypatch):
    import sqlite3
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(n, f"owner{n}.c2.test") for n in range(12)]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    try:
        rows = stage.db.execute("SELECT id,owner,typeof(owner) FROM citation_owner ORDER BY id").fetchall()
        assert len(rows) == len(pairs) and {kind for _id, _owner, kind in rows} == {"integer"}
        assert len({owner for _id, owner, _kind in rows}) == 1
        stage.db.close()
        stage.db = sqlite3.connect(stage.path)
        stage._compact_cache([], (sweep._stage_owner_accounts[rule.id],), drop_raw=True)
        assert stage.db.execute("SELECT id,owner,typeof(owner) FROM citation_owner ORDER BY id").fetchall() == rows
        assert stage._evict_references(4096) == 0
        sweep.finalize()
        candidates = sweep.repo.candidates("h1")
        assert len(candidates) == len(pairs)
        assert all(row["lane"] == "high" and row["event_ids"] for row in candidates)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("admit_small", [False, True])
def test_failed_native_compact_subsets_reuse_exhausted_plan(tmp_path, monkeypatch, admit_small):
    import hashlib
    import sqlite3
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(n, f"protected{n}.c2.test") for n in range(10)]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    try:
        while stage._evict_citations(4096):
            pass
        sweep.budget.disk_total = sweep.budget.physical_used + (16384 if admit_small else 0)
        # Native question text whose compact body is larger than the entire remaining stage file.
        question = "".join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(4096))
        pending = [dns(100+n, question)[0] for n in range(4)]
        small = dns(900, "small.c2.test")[0]
        if admit_small:
            pending.insert(2, small)
        full = []
        original = stage._write_compact
        def write(*args):
            try:
                return original(*args)
            except sqlite3.OperationalError as exc:
                assert "full" in str(exc).lower()
                full.append(len(args[0]))
                raise
        monkeypatch.setattr(stage, "_write_compact", write)
        from romulus.hunt import stage as stage_module
        compact = stage_module.compact_event
        compressed = []
        def counted(event):
            compressed.append(event.id)
            return compact(event)
        monkeypatch.setattr(stage_module, "compact_event", counted)
        before = stage._reference_plan_builds
        stage._put_compact(pending, accounts=(sweep._stage_owner_accounts[rule.id],))
        assert len(compressed) == len(pending)
        assert full.count(1) == 4
        assert stage._reference_plan_builds == before == 1
        assert stage.count() == len(pairs)+int(admit_small)
        assert [event.id for event in stage.load([event.id for event in pending])] == ([small.id] if admit_small else [])
        sweep.finalize()
        rows = sweep.repo.candidates("h1")
        assert len(rows) == len(pairs) and all(row["lane"] == "high" and row["event_ids"] for row in rows)
    finally:
        sweep.close_stage()


def test_actual_full_reclaims_progressively_and_keeps_each_native_group(tmp_path, monkeypatch):
    from romulus.detect.network import PortScan
    from romulus.hunt import sweep as sw
    from tests.test_bounded_starvation import _Listed
    from tests.test_flow_rules import eve, events
    from tests.test_sweep import _complete
    routine, strong = PortScan(), _Listed()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine, strong])
    budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    hits = [eve(f"flow-{group}-{n}", src=f"10.0.0.{group+1}", dport=200+n)
            for group in range(2) for n in range(30)]
    pairs = [dns(100+n, "strong.c2.test") for n in range(20)]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits+[h for _, h in pairs]))
    sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=80)
    stage = sweep._event_stage()
    budget.reclaim_citations(budget.disk_total)
    before = {e.id for e in stage.load([e.id for e in events(*hits)]+[e.id for e, _ in pairs])}
    strong_ids = {e.id for e, _ in pairs}
    reclaimed = []
    original = stage._citation_account.evict_references
    def step(needed):
        count = stage.count()
        progress = original(needed)
        reclaimed.append(count-stage.count())
        return progress
    stage._citation_account.evict_references = step
    owner = _owner(tmp_path, budget, "pressure", strong=True)
    store = KeyedStore(owner, "records", hot=0)
    try:
        for n in range(300):
            assert store.put(str(n), bytes([n % 256])*12000)
            store.trim()
            after = {e.id for e in stage.load(sorted(before))}
            if after != before:
                break
        else:
            pytest.fail("fixture did not reach actual reference pressure")
        assert 0 < len(before-after) < len(before)//2
        assert reclaimed and max(reclaimed) <= 4
        assert len(reclaimed) > 1 and stage._reference_plan_builds == 1
        assert any("SEARCH" in row[3] and "event_time" in row[3] for row in stage.db.execute(
            "EXPLAIN QUERY PLAN SELECT seq,id,reclaim FROM event INDEXED BY event_time "
            "WHERE (seq,id)>(?,?) ORDER BY seq,id LIMIT 128", (0, "")))
        assert strong_ids <= after
        for _key, state in routine.groups.items():  # noqa: PERF102 -- KeyedStore has no values().
            assert any(eid in after for eid in state.held)
        assert budget.physical_used <= budget.disk_total
        with budget.reclamation_write():
            stage._evict_references(4096)
        assert stage._reference_plan_builds == 1
    finally:
        owner.close_spill()
        sweep.close_stage()


def test_native_network_join_retries_full_after_rolling_back_ddl(tmp_path, monkeypatch):
    import sqlite3

    from romulus.detect.correlation import ProcessNetworkLink
    from romulus.evidence.normalize import normalize_hits
    from tests.test_network_correlation import alert, audit_hit, flow, sockaddr, syscall
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    events, _skips, errors = normalize_hits([
        audit_hit("socket", syscall()), audit_hit("address", sockaddr()), flow(), alert()])
    assert not errors
    rule.consume(events)
    staged = {event.id: event for event in rule.drain_staged()}
    rule.bind_loader(lambda ids: [staged[identity] for identity in ids if identity in staged])
    spill = rule.spill()
    spill.flush()
    physical_before = spill.budget.physical_used
    connection = spill.db
    failures, retries = [], []
    class FullJoin:
        def __getattr__(self, name):
            return getattr(connection, name)
        def execute(self, sql, *args):
            if sql.startswith("CREATE TABLE link") and len(failures) < 2:
                failures.append(sql)
                raise sqlite3.OperationalError("database or disk is full")
            return connection.execute(sql, *args)
    spill.db = FullJoin()
    def reclaim():
        assert not connection.in_transaction
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='ep_key'").fetchone()
        assert spill.budget.physical_used == physical_before
        retries.append(True)
        return True
    monkeypatch.setattr(spill.budget, "reclaim_citations_step", reclaim)
    try:
        [match] = rule.finalize()
        assert match.proposed_lane in {"high", "lead"} and match.events
        assert len(failures) == len(retries) == 2
        assert not rule.limits
    finally:
        rule.release_state()


def test_native_network_join_admits_past_legacy_row_cap(tmp_path):
    from romulus.detect.correlation import ProcessNetworkLink
    from romulus.evidence.normalize import normalize_hits
    from tests.test_network_correlation import flow
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    rule.DISK_BUDGET = 1024
    rule.budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    events, _skips, errors = normalize_hits([flow(str(n), sport=40000+n) for n in range(40)])
    assert not errors
    try:
        rule.consume(events)
        rule.spill().flush()
        assert rule.evaluated == 40 and not rule.limits
        assert rule.spill().db.execute("SELECT count(*) FROM net").fetchone()[0] == 40
        assert rule.budget.physical_used < rule.budget.disk_total
    finally:
        rule.release_state()


@pytest.mark.parametrize("fail_coverage", [False, True])
def test_finished_owner_releases_only_after_publication_and_coverage(tmp_path, monkeypatch, fail_coverage):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(1, "first.c2.test"), dns(2, "second.c2.test")]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    close = sweep.close_stage
    monkeypatch.setattr(sweep, "close_stage", lambda: None)
    if fail_coverage:
        def fail(*args, **kwargs):
            raise RuntimeError("coverage write failed")
        monkeypatch.setattr(sweep.repo, "set_rule_cell", fail)
    try:
        if fail_coverage:
            with pytest.raises(RuntimeError, match="coverage write failed"):
                sweep.finalize()
            assert not stage.finished_owners
            assert stage._evict_references(4096) == 0
        else:
            sweep.finalize()
            before = [(row["id"], row["event_ids"]) for row in sweep.repo.candidates("h1")]
            assert len(before) == 2 and all(ids for _identity, ids in before)
            assert stage.finished_owners
            assert stage._evict_references(4096)
            assert stage.count() == 0
            assert [(row["id"], row["event_ids"]) for row in sweep.repo.candidates("h1")] == before
    finally:
        close()


def test_strong_group_keeps_a_witness_across_large_protected_stage(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sw
    from tests.test_bounded_starvation import _Listed
    from tests.test_sweep import _complete
    strong = _Listed()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [strong])
    budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    hits = [dns(n+2, f"singleton{n}.c2.test")[1] for n in range(130)]
    pairs = [dns(1, "strong.c2.test"), dns(200, "strong.c2.test")]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits+[h for _, h in pairs]))
    sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=132)
    stage = sweep._event_stage()
    owner = _owner(tmp_path, budget, "pressure", strong=True)
    store = KeyedStore(owner, "records", hot=0)
    ids = [event.id for event, _hit in pairs]
    try:
        assert len(stage.load(ids)) == 2 and stage.count() >= 132
        for n in range(300):
            if not store.put(str(n), bytes([n % 256])*12000):
                break
            store.trim()
            if len(stage.load(ids)) < 2:
                break
        assert len(stage.load(ids)) == 1
        assert stage.count() == 131
        assert budget.physical_used <= budget.disk_total
        survivor = stage.load(ids)[0].id
        sweep.finalize()
        [candidate] = [row for row in sweep.repo.candidates("h1") if "strong.c2.test" in row["claim"]]
        assert candidate["lane"] == "high" and candidate["event_ids"] == [survivor]
        assert "no citation could be retained" not in str(candidate)
    finally:
        owner.close_spill()
        sweep.close_stage()


@pytest.mark.parametrize("refuse_endpoints", [False, True])
@pytest.mark.parametrize("flush_before", [False, True])
def test_native_join_keeps_only_potential_partners_during_finalization(tmp_path, monkeypatch, refuse_endpoints, flush_before):
    from romulus.detect.correlation import ProcessNetworkLink
    from romulus.evidence.normalize import normalize_hits
    from tests.test_network_correlation import ATTACKER, audit_hit, flow, sockaddr, syscall
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    if refuse_endpoints:
        monkeypatch.setattr(rule.endpoints, "put", lambda *args: False)
    records = [audit_hit("socket", syscall()), audit_hit("address", sockaddr()),
               flow("linked"), flow("unmatched", dst="203.0.113.80")]
    events, _skips, errors = normalize_hits(records)
    assert not errors
    try:
        rule.consume(events)
        if flush_before:
            rule.spill().flush()
        else:
            assert rule.spill().db.execute("SELECT count(*) FROM net").fetchone()[0] == 0
            assert len(rule.spill()._buffers["net"][1]) == 2
        assert list(rule.extra_citation_reference_groups()) == []
        rule.state_budget().finalizing = True
        ids = [identity for _group, refs in rule.extra_citation_reference_groups() for identity in refs]
        if refuse_endpoints:
            assert not ids
            return
        assert ids == [event.id for event in events if event.get("destination.ip") == "203.0.113.80"]
        assert not set(ids) & {event.id for event in events if event.get("destination.ip") == ATTACKER}
    finally:
        rule.release_state()


def test_native_pending_join_flush_recovers_after_actual_full(tmp_path, monkeypatch):
    import sqlite3

    from romulus.detect.bounded import Spill
    from romulus.hunt import sweep as sw
    from tests import throughput_fixture as tf
    tf.patched_sizes(monkeypatch)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir:
                        StateBudget(stage_dir, disk_total=2*2**20, reserve=0))
    full = []
    original = Spill.write
    def write(self, *args, **kwargs):
        if getattr(self.owner, "id", "") != "corr.process_network_link":
            return original(self, *args, **kwargs)
        connection = self.db
        class RecordedFull:
            def __getattr__(self, name):
                return getattr(connection, name)
            def executemany(self, sql, rows):
                try:
                    return connection.executemany(sql, rows)
                except sqlite3.OperationalError as exc:
                    if "full" in str(exc).lower() and sql.startswith("INSERT INTO net "):
                        full.append((self_budget.finalizing, len(self_buffers["net"][1])))
                    raise
        self_budget, self_buffers = self.budget, self._buffers
        self.db = RecordedFull()
        try:
            return original(self, *args, **kwargs)
        finally:
            self.db = connection
    monkeypatch.setattr(Spill, "write", write)
    snapshot = tf.run_stack(tmp_path, docs=tf.build(1))
    assert full and all(finalizing and count for finalizing, count in full)
    [candidate] = [row for row in snapshot["candidates"] if row["rule_id"] == "corr.process_network_link"]
    assert candidate["lane"] == "high" and candidate["event_ids"]


def test_optional_body_steps_use_a_monotonic_cursor_and_reset_for_new_native_events(tmp_path):
    from romulus.hunt.stage import EventStage
    pairs = sorted((dns(n, f"name{n}.example.test") for n in range(20)), key=lambda pair: pair[0].id)
    stage = EventStage(tmp_path)
    try:
        stage.put([event for event, _hit in pairs[4:]], {})
        previous = ""
        for _ in range(4):
            count = stage.db.execute("SELECT count(*) FROM event WHERE typeof(body)='text'").fetchone()[0]
            assert stage._evict_citations(2**30)
            assert stage.db.execute("SELECT count(*) FROM event WHERE typeof(body)='text'").fetchone()[0] == count-4
            assert stage._body_cursor > previous
            previous = stage._body_cursor
        assert stage._evict_citations(4096) == 0
        stage.put([event for event, _hit in pairs[:4]], {})
        assert stage._body_cursor == ""
        assert stage._evict_citations(4096)
        assert stage.db.execute("SELECT count(*) FROM event WHERE typeof(body)='text'").fetchone()[0] == 0
    finally:
        stage.close()


def test_shared_native_network_reference_keeps_unclassified_join_owner(tmp_path, monkeypatch):
    from romulus.detect.correlation import ProcessNetworkLink
    from romulus.detect.network import PortScan
    from romulus.evidence.normalize import normalize_hits
    from romulus.hunt import sweep as sw
    from tests.test_network_correlation import audit_hit, flow, sockaddr, syscall
    from tests.test_sweep import _complete
    routine, join = PortScan(), ProcessNetworkLink()
    records = [audit_hit("socket", syscall()), audit_hit("address", sockaddr()), flow("first"),
               flow("later", start="2024-11-18T14:26:41.050000+0000", sport=51001)]
    events, _skips, errors = normalize_hits(records)
    assert not errors
    [shared] = [event.id for event in events if event.family == "net_flow"
                and any(ref.native_id == "first" for ref in event.raw)]
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine, join])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, records))
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    try:
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(records))
        stage = sweep._event_stage()
        sweep.budget.finalizing = True
        with sweep.budget.reclamation_write():
            stage._evict_references(4096)
        assert [event.id for event in stage.load([shared])] == [shared]
        sweep.finalize()
        [candidate] = [row for row in sweep.repo.candidates("h1") if row["rule_id"] == join.id]
        assert shared in candidate["event_ids"]
    finally:
        sweep.close_stage()


def test_native_nonpublishing_flow_flood_keeps_a_late_indicator_witness(tmp_path, monkeypatch):
    from romulus.detect.network import PortScan
    from romulus.hunt import sweep as sw
    from tests.test_bounded_starvation import _Listed
    from tests.test_flow_rules import eve
    from tests.test_sweep import _complete
    routine, strong = PortScan(), _Listed()
    routine.groups.hot_size = routine.requests.hot_size = 1
    monkeypatch.setattr(sw, "fresh_pack", lambda: [routine, strong])
    budget = StateBudget(tmp_path, disk_total=400000, reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    try:
        for batch in range(8):
            hits = [eve(f"routine-{batch}-{n}", src=f"10.{batch}.{n}.1", dst=f"172.16.{batch}.{n}",
                        dport=443, start=START+timedelta(seconds=batch*100+n)) for n in range(100)]
            monkeypatch.setattr(sw, "execute", lambda client, intent, contract, hits=hits: _complete(intent, hits))
            sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(hits))
        event, hit = dns(900, "late.c2.test")
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [hit]))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=1)
        stage = sweep._event_stage()
        assert stage._reference_plan_builds and stage.load([event.id])
        assert not strong.capped and budget.physical_used <= budget.disk_total
        sweep.finalize()
        [candidate] = [row for row in sweep.repo.candidates("h1") if row["rule_id"] == strong.id]
        assert candidate["lane"] == "high" and candidate["event_ids"] == [event.id]
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("initial", [1, 24])
def test_native_nonpublishing_group_refreshes_or_retains_witness_before_later_crossing(tmp_path, monkeypatch, initial):
    from romulus.detect.network import PortScan
    from romulus.hunt import sweep as sw
    from tests.test_flow_rules import eve
    from tests.test_sweep import _complete
    rule = PortScan()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=tmp_path)
    hits = [eve(f"before-{n}", src="10.1.1.1", dst="203.0.113.8", dport=100+n,
                start=START+timedelta(seconds=n)) for n in range(initial)]
    try:
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=len(hits))
        stage = sweep._event_stage()
        with sweep.budget.reclamation_write():
            while stage._evict_references(4096):
                pass
        assert stage.count() == (0 if initial == 1 else 1)
        # Between the existing bounds, beyond the full examples and named-port sample in the 24-port case.
        late = eve("late-middle", src="10.1.1.1", dst="203.0.113.8", dport=100+initial,
                   start=START+timedelta(seconds=12))
        monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [late]))
        sweep.run_partition("romulus-network-logs", None, [], sweep.window, est=1)
        assert stage.count() >= 1
        if initial == 24:
            assert rule.reportable(rule.groups.peek(("10.1.1.1", "203.0.113.8")))
            sweep.finalize()
            [candidate] = sweep.repo.candidates("h1")
            assert candidate["lane"] == "lead"
            assert candidate["event_ids"]
            assert "no citation could be retained" not in str(candidate)
    finally:
        sweep.close_stage()
