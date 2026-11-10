"""Evidence-based ranking: entity factors, the evidence bar, the Reported set, network endpoints and storage."""
from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select

from romulus.decide import rank as model
from romulus.hunt.rank import (
    PASS_BEFORE_EXPANSION,
    PASS_FINAL,
    compute_rank_pass,
    expansion_seeds,
    rank_unranked,
    run_rank_pass,
)
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 10, 0, tzinfo=UTC)
END = datetime(2024, 11, 18, 17, 30, tzinfo=UTC)
PRIOR = {"urgent": 80.0, "high": 50.0, "lead": 30.0, "context": 10.0, "suppressed": 0.0}


def _repo(path=":memory:", hunt_id="h1") -> Repo:
    engine = make_engine(path)
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt(hunt_id, {"window": {"start": START.isoformat(), "end": END.isoformat()}}, "d", "test")
    return repo


def _row(cid, rule, *, lane="lead", host=None, account=None, ts=START, attack=None, provenance="deterministic",
         entities=None, hunt_id="h1", source_anchor_id=None, priority=None):
    if entities is None:
        entities = ([["host", host, "host"]] if host else []) + ([["account", account, "actor"]] if account else [])
    gates = {"observation": "pass"}
    if attack:
        gates["_attack"] = list(attack)
    return {
        "id": cid, "hunt_id": hunt_id, "rule_id": rule, "rule_version": "1", "claim": f"{rule} on {host}",
        "claim_type": "observed_action", "event_ids": [], "context_event_ids": [], "predicate_fields": [],
        "entities": entities, "ts": ts, "severity": "medium", "confidence": "medium", "lane": lane,
        "priority": PRIOR[lane] if priority is None else priority, "priority_reasons": [], "gate_results": gates,
        "benign_alternatives": [], "next_checks": [], "group_key": "", "source_case_id": None,
        "source_anchor_id": source_anchor_id, "source_link_id": None, "provenance": provenance,
        "agent_hypothesis_id": None, "created_at": utcnow(),
    }


def _insert(repo: Repo, rows: list[dict]) -> None:
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert(), rows)


def _ranks(repo, pass_no=PASS_FINAL, hunt_id="h1"):
    with repo.engine.connect() as connection:
        findings = {row["candidate_id"]: dict(row) for row in connection.execute(select(t.finding_rank).where(
            t.finding_rank.c.hunt_id == hunt_id, t.finding_rank.c["pass"] == pass_no)).mappings()}
        entities = {(row["entity_kind"], row["entity"]): dict(row) for row in connection.execute(
            select(t.entity_rank).where(t.entity_rank.c.hunt_id == hunt_id,
                                        t.entity_rank.c["pass"] == pass_no)).mappings()}
    return findings, entities


def _event(repo, eid, host, family, ips, ts=START + timedelta(hours=1), hunt_id="h1"):
    with repo.engine.begin() as connection:
        connection.execute(t.typed_event.insert().values(
            id=eid, hunt_id=hunt_id, family=family, ts=ts, host=host, raw_ids=[], normalizer="test",
            event={"id": eid, "family": family, "host": host,
                   "fields": {"host.ip": {"value": ips, "origin": "raw:host.ip"}}}))


# -- the evidence bar -----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("evidence, met", [
    (model.EntityEvidence(1, (), 0, 0, 80.0), True),                                   # U
    (model.EntityEvidence(0, (), 0, 0, 30.0), False),                                  # U minus one
    (model.EntityEvidence(0, ("credential-access", "execution"), 2, 0, 30.0), True),   # T>=2
    (model.EntityEvidence(0, ("execution",), 2, 0, 30.0), False),                      # T minus one
    (model.EntityEvidence(0, (), 3, 1, 30.0), True),                                   # R>=3 with C>=1
    (model.EntityEvidence(0, (), 2, 1, 30.0), False),                                  # R minus one
    (model.EntityEvidence(0, (), 3, 0, 30.0), False),                                  # C minus one
])
def test_evidence_bar_cases(evidence, met):
    assert (model.evidence_bar(evidence) is not None) is met
    assert model.entity_score(evidence)[1] is met


def test_entity_score_weights_and_reasons():
    score, reported, reasons = model.entity_score(model.EntityEvidence(1, ("execution", "persistence"), 3, 2, 50.0))
    assert score == 40 + 20 + 15 + 6 + 50
    assert reported and any("U=1 (+40)" in reason for reason in reasons)


def _bar_hunt(rows):
    repo = _repo()
    _insert(repo, rows)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    return _ranks(repo)


def test_bar_through_a_pass_tactics_rules_and_cooccurrence():
    findings, entities = _bar_hunt([
        # T>=2 on h-t: execution + credential access
        _row("t1", "r.exec", host="h-t", attack=["T1059"]),
        _row("t2", "r.cred", host="h-t", attack=["T1003"], ts=START + timedelta(hours=5)),
        # T=1 on h-t1: two rules of one tactic
        _row("u1", "r.exec", host="h-t1", attack=["T1059"]),
        _row("u2", "r.exec2", host="h-t1", attack=["T1059.001"], ts=START + timedelta(hours=5)),
        # R=3, C=1 on h-r: two of three rules within an hour
        _row("r1", "r.a", host="h-r"), _row("r2", "r.b", host="h-r", ts=START + timedelta(minutes=60)),
        _row("r3", "r.c", host="h-r", ts=START + timedelta(hours=5)),
        # R=3, C=0 on h-rc: all more than an hour apart
        _row("s1", "r.a", host="h-rc"), _row("s2", "r.b", host="h-rc", ts=START + timedelta(minutes=61)),
        _row("s3", "r.c", host="h-rc", ts=START + timedelta(hours=5)),
        # R=2, C=1 on h-r2
        _row("v1", "r.a", host="h-r2"), _row("v2", "r.b", host="h-r2", ts=START + timedelta(minutes=5)),
    ])
    assert entities[("host", "h-t")]["reported"] and entities[("host", "h-t")]["tactics"] == [
        "credential-access", "execution"]
    assert not entities[("host", "h-t1")]["reported"]
    assert entities[("host", "h-r")]["reported"] and entities[("host", "h-r")]["cooccur"] == 1
    assert not entities[("host", "h-rc")]["reported"] and entities[("host", "h-rc")]["cooccur"] == 0
    assert not entities[("host", "h-r2")]["reported"]
    assert {cid for cid, row in findings.items() if row["reported"]} == {"t1", "t2", "r1", "r2", "r3"}


def test_confirmed_findings_are_always_reported_whatever_their_entity():
    findings, entities = _bar_hunt([
        _row("c-none", "r.confirmed", lane="urgent", entities=[]),
        _row("c-host", "r.confirmed", lane="urgent", host="quiet"),
        _row("p-host", "r.lead", host="quiet", ts=START + timedelta(hours=3)),
        _row("p-other", "r.lead", host="other"),
    ])
    assert findings["c-none"]["reported"] and findings["c-none"]["entity_kind"] == "unattributed"
    assert findings["c-host"]["reported"]
    # U>=1 on the confirmed finding's host reports its pool findings too
    assert findings["p-host"]["reported"] and entities[("host", "quiet")]["confirmed"] == 1
    assert not findings["p-other"]["reported"]


def test_every_pool_finding_is_ranked_and_context_stays_outside():
    rows = [_row(f"p{index}", f"r{index % 4}", lane=("high", "lead")[index % 2], host=f"h{index % 3}",
                 ts=START + timedelta(minutes=17 * index)) for index in range(40)]
    rows += [_row("ctx", "r.ctx", lane="context", host="h0"), _row("sup", "r.sup", lane="suppressed", host="h1")]
    findings, _ = _bar_hunt(rows)
    assert set(findings) == {f"p{index}" for index in range(40)}
    assert sorted(row["position"] for row in findings.values()) == list(range(1, 41))


# -- recurring fleet-wide behaviour ---------------------------------------------------------------------------------
def _fleet_rows(*, burst: bool, hosts: int, fleet_hosts: int):
    rows = []
    for index in range(fleet_hosts):
        offset = timedelta(minutes=index) if burst else timedelta(minutes=42 * index)
        rows.append(_row(f"f{index}", "r.fleet", host=f"h{index}", ts=START + offset))
    rows.append(_row("f-last", "r.fleet", host="h0",
                     ts=START + (timedelta(minutes=10) if burst else timedelta(hours=7))))
    rows += [_row(f"o{index}", "r.other", host=f"h{index}") for index in range(fleet_hosts, hosts)]
    return rows


def test_recurring_fleet_rule_over_the_whole_window_is_penalized():
    findings, entities = _bar_hunt(_fleet_rows(burst=False, hosts=12, fleet_hosts=10))
    assert findings["f0"]["score"] == entities[("host", "h0")]["score"] + PRIOR["lead"] - model.FLEET_PENALTY
    assert any("recurring fleet-wide rule r.fleet: 10 of 12 hosts" in reason for reason in findings["f0"]["reasons"])
    # the rule counts toward no entity's rules
    assert entities[("host", "h0")]["rules"] == 0
    assert findings["o11"]["score"] == entities[("host", "h11")]["score"] + PRIOR["lead"]


def test_the_same_rule_in_a_ten_minute_burst_is_not_penalized():
    findings, entities = _bar_hunt(_fleet_rows(burst=True, hosts=12, fleet_hosts=10))
    assert findings["f0"]["score"] == entities[("host", "h0")]["score"] + PRIOR["lead"]
    assert entities[("host", "h0")]["rules"] == 1


def test_fewer_than_three_hosts_means_no_penalty():
    findings, entities = _bar_hunt(_fleet_rows(burst=False, hosts=2, fleet_hosts=2))
    assert findings["f0"]["score"] == entities[("host", "h0")]["score"] + PRIOR["lead"]
    assert not any("fleet" in reason for reason in findings["f0"]["reasons"])


def test_fleet_condition_thresholds():
    window = 7.5 * 3600
    assert model.fleet_recurring(10, 12, window, window)
    assert not model.fleet_recurring(10, 12, 600, window)
    assert not model.fleet_recurring(2, 2, window, window)
    assert model.fleet_recurring(3, 5, window / 2, window) and not model.fleet_recurring(2, 5, window, window)


# -- determinism ------------------------------------------------------------------------------------------------
def test_ranking_is_deterministic_and_independent_of_insert_order():
    rows = []
    for index in range(120):
        rows.append(_row(f"c{index:03d}", f"r{index % 7}", lane=("urgent", "high", "lead", "lead")[index % 4],
                         host=f"h{index % 9}", account=f"name:corp\\u{index % 5}",
                         attack=[("T1059", "T1003", "T1021", "T1046")[index % 4]] if index % 3 else None,
                         ts=START + timedelta(minutes=(index * 37) % 400)))
    results = []
    for seed in (1, 2, 3):
        shuffled = list(rows)
        random.Random(seed).shuffle(shuffled)
        repo = _repo()
        _insert(repo, [dict(row) for row in shuffled])
        compute_rank_pass(repo, "h1", PASS_FINAL, batch_size=7)
        results.append(_ranks(repo))
    assert results[0] == results[1] == results[2]


def test_a_resumed_pass_recomputes_the_same_ranks():
    repo = _repo()
    _insert(repo, [_row(f"c{index}", f"r{index % 3}", host=f"h{index % 2}", ts=START + timedelta(minutes=index))
                   for index in range(20)])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    first = _ranks(repo)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    assert _ranks(repo) == first


# -- agent findings never raise their own targets ------------------------------------------------------------------
def test_agent_findings_are_ranked_but_never_count_toward_entities():
    base = [_row("d1", "r.exec", host="target", attack=["T1059"])]
    agent = _row("a1", "agent.finding", lane="high", host="target", attack=["T1003"], provenance="agent",
                 priority=90.0)
    without, with_agent = _repo(), _repo()
    _insert(without, base)
    _insert(with_agent, [*base, agent])
    compute_rank_pass(without, "h1", PASS_FINAL)
    compute_rank_pass(with_agent, "h1", PASS_FINAL)
    _plain, plain_entities = _ranks(without)
    findings, entities = _ranks(with_agent)
    for field in ("score", "tactics", "rules", "confirmed", "cooccur", "reported"):
        assert entities[("host", "target")][field] == plain_entities[("host", "target")][field]
    assert findings["a1"]["score"] == entities[("host", "target")]["score"] + 90.0
    assert not findings["a1"]["reported"]
    assert any("AI agent finding" in reason for reason in findings["a1"]["reasons"])
    # a finding stored after the pass is ranked from the stored entity scores
    late = rank_unranked(with_agent, "h1", [agent])
    assert late["a1"]["score"] == findings["a1"]["score"] and late["a1"]["reported"] is False


# -- network endpoints -----------------------------------------------------------------------------------------------
def _flow(cid, endpoints, rule="net.rule", lane="lead", ts=START):
    return _row(cid, rule, lane=lane, ts=ts,
                entities=[["host", "zeek-sensor-1", "observer"],
                          *[["ip", address, role] for address, role in zip(endpoints, ("src", "dst"))]])


def test_zeek_only_hunt_ranks_endpoints_and_never_the_sensor():
    findings, entities = _bar_hunt([
        _flow("n1", ["10.0.0.5", "203.0.113.9"]),
        _flow("n2", ["10.0.0.5", "10.0.0.7"], rule="net.other", ts=START + timedelta(minutes=5)),
        _flow("n3", ["198.51.100.1", "203.0.113.9"], rule="net.third"),
    ])
    assert ("host", "zeek-sensor-1") not in entities
    assert {key for key in entities} == {("host", "10.0.0.5"), ("host", "10.0.0.7"), ("ip", "203.0.113.9"),
                                         ("ip", "198.51.100.1")}
    # internal endpoint first
    assert (findings["n1"]["entity_kind"], findings["n1"]["entity"]) == ("host", "10.0.0.5")
    assert entities[("host", "10.0.0.5")]["rules"] == 2 and entities[("ip", "203.0.113.9")]["rules"] == 2


def test_a_network_finding_without_an_endpoint_is_unattributed_and_still_listed():
    findings, entities = _bar_hunt([_row("n0", "net.alert", entities=[["host", "zeek-sensor-1", "observer"]])])
    assert findings["n0"]["entity_kind"] == "unattributed" and findings["n0"]["entity"] is None
    assert findings["n0"]["score"] == PRIOR["lead"] and not entities


def test_endpoints_are_capped_at_two_internal_first():
    entities = [["host", "s", "observer"], ["ip", "203.0.113.1", "src"], ["ip", "203.0.113.2", "dst"],
                ["ip", "10.1.1.1", "dst"]]
    internal = model.address_is_internal(__import__("romulus.detect.netdef", fromlist=["x"]).SiteNetworks.default())
    assert model.ranking_entities(entities, is_internal=internal) == [("host", "10.1.1.1"), ("ip", "203.0.113.1")]


def test_an_unambiguous_address_joins_the_host_and_an_ambiguous_one_stays_apart():
    repo = _repo()
    _event(repo, "e1", "web01", "process_exec", ["10.0.0.5", "fe80::1"])
    _event(repo, "e2", "app01", "process_exec", "10.0.0.6")
    _event(repo, "e3", "app02", "auth", ["10.0.0.6"])
    # a sensor's own address never maps a host
    _event(repo, "e4", "zeek-sensor-1", "net_flow", ["10.0.0.7"])
    _insert(repo, [
        _row("h1", "host.rule", host="web01", attack=["T1059"]),
        _flow("n1", ["10.0.0.5", "203.0.113.9"], rule="net.rule", ts=START + timedelta(minutes=10)),
        _flow("n2", ["10.0.0.6", "203.0.113.9"], rule="net.rule2"),
        _flow("n3", ["10.0.0.7", "203.0.113.9"], rule="net.rule3"),
    ])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    findings, entities = _ranks(repo)
    assert entities[("host", "web01")]["rules"] == 2 and entities[("host", "web01")]["cooccur"] == 1
    assert ("host", "10.0.0.5") not in entities
    assert ("host", "10.0.0.6") in entities and ("host", "app01") not in entities
    assert ("host", "10.0.0.7") in entities and ("host", "zeek-sensor-1") not in entities
    # the external end collects all three network rules; the finding ranks by its best entity
    assert entities[("ip", "203.0.113.9")]["rules"] == 3
    assert (findings["n1"]["entity_kind"], findings["n1"]["entity"]) == ("ip", "203.0.113.9")


def test_shared_principals_are_not_entities():
    assert model.ranking_entities([["host", "a", "host"], ["account", "sid:s-1-5-18", "actor"],
                                   ["account", "root", "actor"], ["account", "name:corp\\alice", "actor"]]) == [
        ("host", "a"), ("account", "name:corp\\alice")]


# -- co-occurrence scan -----------------------------------------------------------------------------------------------
def test_cooccurrence_window_is_inclusive_and_capped():
    scan = model.CooccurrenceScan()
    scan.add("a", START)
    scan.add("b", START + timedelta(minutes=60))
    scan.add("c", START + timedelta(minutes=121))
    assert scan.pairs == {("a", "b")}
    many = model.CooccurrenceScan()
    for index in range(8):
        many.add(f"r{index}", START + timedelta(minutes=index))
    assert many.count == model.COOCCURRENCE_CAP and many.full


# -- passes and expansion seeds -------------------------------------------------------------------------------------
def test_pass_one_ranks_only_what_the_stages_before_expansion_found():
    repo = _repo()
    _insert(repo, [_row("s1", "r.a", host="h"), _row("x1", "r.b", host="h", source_anchor_id="s1")])
    compute_rank_pass(repo, "h1", PASS_BEFORE_EXPANSION)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    assert set(_ranks(repo, PASS_BEFORE_EXPANSION)[0]) == {"s1"}
    assert set(_ranks(repo, PASS_FINAL)[0]) == {"s1", "x1"}


def test_seeds_are_the_reported_set_in_rank_order():
    repo = _repo()
    _insert(repo, [
        _row("c1", "r.confirmed", lane="urgent", host="a"),
        _row("p1", "r.lead", host="a", ts=START + timedelta(hours=1)),
        _row("q1", "r.high", lane="high", host="b"),
    ])
    compute_rank_pass(repo, "h1", PASS_BEFORE_EXPANSION)
    seeds = [candidate["id"] for candidate, _score in expansion_seeds(repo, "h1")]
    assert seeds == ["c1", "p1"]


def test_seed_floor_when_no_pool_finding_is_reported():
    repo = _repo()
    _insert(repo, [
        _row("c1", "r.confirmed", lane="urgent", entities=[]),
        _row("h1", "r.h1", lane="high", host="b"), _row("h2", "r.h2", lane="high", host="c"),
        _row("l1", "r.l1", host="d", priority=70.0), _row("l2", "r.l2", host="e", priority=10.0),
    ])
    compute_rank_pass(repo, "h1", PASS_BEFORE_EXPANSION)
    seeds = [candidate["id"] for candidate, _score in expansion_seeds(repo, "h1")]
    # the confirmed finding plus the two top-ranked pool findings: as many as the high lane would have seeded
    assert seeds == ["c1", "l1", "h1"]


def test_no_ranking_means_no_ranked_seeds():
    assert expansion_seeds(_repo(), "h1") is None


def test_a_failed_pass_is_recorded_and_leaves_no_stale_ranks(monkeypatch):
    repo = _repo()
    _insert(repo, [_row("c1", "r.a", host="h")])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    import romulus.hunt.rank as rank_module

    def broken(*_args, **_kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(rank_module, "compute_rank_pass", broken)
    summary = run_rank_pass(repo, "h1", PASS_FINAL)
    assert summary["status"] == "failed" and not repo.has_rank_pass("h1", PASS_FINAL)
    assert repo.latest_audit("h1", "hunt.rank_pass_2_summary")["detail"]["status"] == "failed"


# -- storage ---------------------------------------------------------------------------------------------------------
def test_delete_hunt_removes_its_ranks(tmp_path):
    repo = _repo(tmp_path / "rank.db")
    _insert(repo, [_row("c1", "r.a", host="h")])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    assert repo.has_rank_pass("h1", PASS_FINAL)
    counts = repo.delete_hunt("h1", "lead")
    assert counts["finding_ranks"] == 1 and counts["entity_ranks"] == 1
    with repo.engine.connect() as connection:
        assert connection.execute(select(t.finding_rank)).all() == []
        assert connection.execute(select(t.entity_rank)).all() == []


def test_rank_migration_up_down_up(tmp_path):
    from alembic import command

    from tests.test_local_content_migration import config
    engine = make_engine(tmp_path / "migrate.db")
    with engine.begin() as connection:
        command.upgrade(config(connection), "0035")
        connection.exec_driver_sql(
            "INSERT INTO hunt (id, created_at, created_by, manifest, manifest_digest, execution_state) "
            "VALUES ('h1', '2026-01-01', 'test', '{}', 'd', 'planned')")
    for direction, revision in (("upgrade", "0037"), ("downgrade", "0035"), ("upgrade", "0037")):
        with engine.begin() as connection:
            getattr(command, direction)(config(connection), revision)
            tables = set(connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'").scalars())
            assert ({"finding_rank", "entity_rank"} <= tables) == (revision == "0037")
            assert connection.exec_driver_sql("SELECT count(*) FROM hunt").scalar() == 1
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO finding_rank (hunt_id, \"pass\", candidate_id, position, score, reported, reasons) "
            "VALUES ('h1', 2, 'c', 1, 1.0, 1, '[]')")


# -- mission scale -----------------------------------------------------------------------------------------------
@pytest.mark.slow
def test_a_pass_over_200k_candidates_and_20k_hosts_stays_within_its_pages(tmp_path):
    repo = _repo(tmp_path / "scale.db")
    rules = [f"rule.{index}" for index in range(60)]
    techniques = ["T1059", "T1003", "T1021", "T1046", "T1053", "T1071"]
    total, hosts = 200_000, 20_000
    rng = random.Random(7)
    with repo.engine.begin() as connection:
        batch = []
        for index in range(total):
            host = f"host-{index % hosts:05d}"
            lane = "urgent" if index % 997 == 0 else ("high" if index % 5 == 0 else "lead")
            rule = rules[rng.randrange(len(rules))]
            batch.append(_row(f"c{index:07d}", rule, lane=lane, host=host,
                              account=f"name:corp\\u{index % 3000}",
                              attack=[techniques[hash(rule) % len(techniques)]] if index % 2 else None,
                              ts=START + timedelta(seconds=rng.randrange(int((END - START).total_seconds())))))
            if len(batch) == 5000:
                connection.execute(t.candidate.insert(), batch)
                batch = []
    statements = []
    event.listen(repo.engine, "before_cursor_execute", lambda *args: statements.append(1))
    batch_size = 2000
    summary = compute_rank_pass(repo, "h1", PASS_FINAL, batch_size=batch_size)
    # every page held at most one page of rows (finding/entity pairs: at most two entities per finding)
    assert summary["peak_rows"] <= 2 * batch_size
    assert summary["population_pages"] == total // batch_size
    # statements grow with pages, never with rows: population, entity, timeline and finding pages, each a read plus
    # a bounded number of writes
    entity_count = summary["entities"]
    pages = (total // batch_size) * 2 + (entity_count // batch_size + 1) + (2 * total // batch_size + 1)
    assert summary["queries"] <= 20 + 6 * pages
    assert len(statements) <= summary["queries"] + 50
    assert summary["ranked_findings"] == total and entity_count == hosts + 3000
    print(json.dumps({key: summary[key] for key in (
        "ranked_findings", "entities", "reported_entities", "reported_findings", "population_pages", "peak_rows",
        "queries")}))


# -- outputs ---------------------------------------------------------------------------------------------------------
def test_ranked_manifest_and_reports_follow_the_headline_structure():
    import tempfile
    import zipfile
    from pathlib import Path

    from romulus.report import executive
    from romulus.report.manifest import build_manifest, canonical_manifest
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_finding

    repo, finding_id = _repo_with_finding()
    stored = {key: value for key, value in repo.candidate(finding_id).items() if key != "created_at"}
    # a quiet lead on another host, then an agent finding stored after the pass
    repo.save_candidate({**stored, "id": "quiet-lead", "lane": "lead", "priority": 20.0,
                         "entities": [["host", "quiet01", "host"]], "claim": "quiet lead"})
    compute_rank_pass(repo, "h1", PASS_FINAL)
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert().values(
            **{**stored, "id": "agent-late", "lane": "high", "priority": 40.0, "provenance": "agent",
               "entities": [["host", "quiet01", "host"]], "claim": "agent lead", "created_at": utcnow()}))
    manifest = build_manifest(repo, "h1", "test")
    by_id = {finding["id"]: finding for finding in manifest["findings"]}
    assert set(by_id) == {finding_id, "quiet-lead", "agent-late"}
    for finding in manifest["findings"]:
        assert {"rank", "entity", "reported", "rank_reasons", "lane"} <= set(finding)
    assert by_id["quiet-lead"]["reported"] is False
    assert by_id["quiet-lead"]["entity"] == {"kind": "host", "value": "quiet01"}
    assert by_id["agent-late"]["rank_position"] is None and by_id["agent-late"]["rank"] is not None
    assert manifest["ranking"]["status"] == "complete"
    assert manifest["entities"][-1]["value"] == "quiet01"
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    markdown = render(manifest)
    headline = [markdown.index(text) for text in (
        "### Confirmed", "### Reported entities", "### Ranked findings (not reported)", "## Finding details")]
    assert headline == sorted(headline)
    assert "rule estimate: lead" in markdown and "quiet lead" in markdown
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "executive.docx"
        executive.write(manifest, path, "technical.md")
        with zipfile.ZipFile(path) as archive:
            document = archive.read("word/document.xml").decode()
    assert document.index("Confirmed") < document.index("Ranked findings (not reported)")
    canonical = canonical_manifest(repo, "h1")
    assert all("rank_position" not in finding and "rank" in finding for finding in canonical["findings"])
