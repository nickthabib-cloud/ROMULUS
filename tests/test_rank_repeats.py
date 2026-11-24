"""Repeated leads in the final order: the first REPEAT_FULL_SHARE findings of one rule listed under one entity inherit
the entity's score in full, each further lead a harmonic share of it. Lanes, sections, the Reported set and every
confirmed or high finding's score are unchanged, and nothing leaves the order."""
from __future__ import annotations

import json
import random
from datetime import timedelta

import pytest

from romulus.decide import rank as model
from romulus.hunt.rank import (
    PASS_BEFORE_EXPANSION,
    PASS_FINAL,
    compute_rank_pass,
    place_late_findings,
    rank_unranked,
)
from tests.test_evidence_rank import START, _insert, _ranks, _repo, _row


def _order(findings: dict) -> list[str]:
    """The product order: section, then position."""
    return sorted(findings, key=lambda cid: (findings[cid]["section"], findings[cid]["position"]))


def _lanes(rows) -> dict[str, str]:
    return {row["id"]: row["lane"] for row in rows}


def _ranked(rows, monkeypatch=None, *, full_share=None, pass_no=PASS_FINAL, batch_size=2000):
    repo = _repo()
    _insert(repo, [dict(row) for row in rows])
    if monkeypatch is not None and full_share is not None:
        monkeypatch.setattr(model, "REPEAT_FULL_SHARE", full_share)
    compute_rank_pass(repo, "h1", pass_no, batch_size=batch_size)
    if monkeypatch is not None:
        monkeypatch.undo()
    return repo, *_ranks(repo, pass_no)


# -- the pattern: one busy host, many same-rule leads, other hosts with mid-score network findings ---------------------
def _busy_rows(admin_leads=8):
    """A host with an attack high and other strong findings across tactics, carrying many leads of one routine rule
    (a stronger prior than the network rules'), and three hosts with network findings of a somewhat weaker entity."""
    minute = timedelta(minutes=1)
    rows = [
        _row("b-priv", "host.priv_broker", lane="high", host="srv", attack=["T1548.003"], ts=START, priority=60),
        _row("b-cred", "host.cred_args", lane="high", host="srv", attack=["T1003"], ts=START + minute, priority=50),
        _row("b-stop", "host.log_stop", lane="high", host="srv", attack=["T1489"], ts=START + 2 * minute, priority=50),
        _row("b-web", "web.scan_burst", host="srv", attack=["T1595"], ts=START + 3 * minute, priority=40),
    ]
    rows += [_row(f"b-admin{index}", "host.account_change", host="srv", attack=["T1136"],
                  ts=START + (4 + index) * minute, priority=50) for index in range(admin_leads)]
    for host in ("n1", "n2", "n3"):
        rows += [
            _row(f"{host}-sweep", "net.sweep", lane="high", host=host, attack=["T1046"], ts=START + 30 * minute,
                 priority=40),
            _row(f"{host}-c2", "net.long_external", host=host, attack=["T1071"], ts=START + 31 * minute, priority=40),
            _row(f"{host}-exfil", "net.exfil", host=host, attack=["T1041"], ts=START + 32 * minute, priority=40),
            _row(f"{host}-scan", "net.port_scan", host=host, attack=["T1595"], ts=START + 33 * minute, priority=40),
        ]
    return rows


def test_many_routine_leads_on_a_busy_host_no_longer_fill_the_top(monkeypatch):
    rows = _busy_rows()
    _repo_before, before, entities = _ranked(rows, monkeypatch, full_share=10**9)
    _repo_after, after, _entities = _ranked(rows)
    srv = entities[("host", "srv")]["score"]
    net = entities[("host", "n1")]["score"]
    assert srv > net                                        # the busy host has the stronger case
    admin = [f"b-admin{index}" for index in range(8)]
    network = [row["id"] for row in rows if row["id"][:2] in ("n1", "n2", "n3")]
    # before: the routine leads inherit the host's whole score and fill the top ten; no network finding is in it
    top_before = _order(before)[:10]
    assert sum(cid in admin for cid in top_before) >= 6 and not set(top_before) & set(network)
    # after: two of them keep the full share, later ones a harmonic share, so every network finding outranks the
    # fourth and later of them
    order = _order(after)
    assert sum(cid in admin for cid in order[:10]) <= model.REPEAT_FULL_SHARE + 1
    assert set(network) & set(order[:10])
    fourth = min(order.index(cid) for cid in admin[3:])
    assert all(order.index(cid) < fourth for cid in network)
    for index, cid in enumerate(admin, start=1):
        share = 1.0 if index <= model.REPEAT_FULL_SHARE else model.REPEAT_FULL_SHARE / index
        assert after[cid]["score"] == pytest.approx(srv * share + 50)
        assert (f"lead {index} of host.account_change" in str(after[cid]["reasons"])) is (share < 1)
    # every high and the busy host's other findings keep their scores, and their places at the top
    assert order[:3] == ["b-priv", "b-cred", "b-stop"] and _order(before)[:3] == order[:3]
    for cid in before:
        if not cid.startswith("b-admin"):
            assert after[cid]["score"] == before[cid]["score"], cid
        for field in ("reported", "section", "entity_kind", "entity"):
            assert after[cid][field] == before[cid][field], (cid, field)
    assert set(after) == set(before)                        # nothing leaves the order


def test_a_host_whose_findings_are_one_attack_chain_stays_on_top(monkeypatch):
    """Eight stages of one intrusion on one host, mostly leads, each seen one to three times, beside twenty hosts that
    each meet the evidence bar on their own: the whole chain stays above every other host's findings, as it did with
    full inheritance."""
    minute = timedelta(minutes=1)
    chain = [("r.phish", "T1566", "high", 1), ("r.exec", "T1059", "lead", 2), ("r.task", "T1053.005", "lead", 3),
             ("r.dump", "T1003", "high", 1), ("r.discover", "T1046", "lead", 3), ("r.lateral", "T1021", "lead", 2),
             ("r.c2", "T1071", "lead", 3), ("r.exfil", "T1041", "lead", 2)]
    rows = [_row(f"v-{rule}-{n}", rule, lane=lane, host="victim", attack=[technique],
                 ts=START + (10 * stage + n) * minute)
            for stage, (rule, technique, lane, times) in enumerate(chain) for n in range(times)]
    for host in range(20):
        rows += [_row(f"o{host:02d}-{n}", f"r.other{n}", lane=("high", "lead")[n], host=f"other{host:02d}",
                      attack=[["T1046", "T1595"][n]], ts=START + timedelta(hours=2, minutes=host + n))
                 for n in range(2)]
    _repo_before, before, _ = _ranked(rows, monkeypatch, full_share=10**9)
    _repo_after, after, entities = _ranked(rows)
    assert all(entities[("host", f"other{host:02d}")]["reported"] for host in range(20))
    order = _order(after)
    victim = [row["id"] for row in rows if row["id"].startswith("v-")]
    assert set(order[:len(victim)]) == set(victim) == set(_order(before)[:len(victim)])
    # the third finding of a rule is a repeat: it ranks lower, still above every other host
    assert after["v-r.c2-2"]["score"] < before["v-r.c2-2"]["score"]


# -- the hard rules -------------------------------------------------------------------------------------------------
def _random_rows(seed, count=400):
    rng = random.Random(seed)
    techniques = ["T1059", "T1003", "T1021", "T1046", "T1071", "T1136", "T1548.003", "T1595", "T1041"]
    rows = []
    for index in range(count):
        lane = rng.choice(("urgent", "high", "high", "lead", "lead", "lead", "lead", "context"))
        rows.append(_row(f"c{index:04d}", f"r{rng.randrange(8)}", lane=lane, host=f"h{rng.randrange(12)}",
                         account=f"name:corp\\u{rng.randrange(6)}" if rng.random() < 0.3 else None,
                         attack=[rng.choice(techniques)] if rng.random() < 0.8 else None,
                         ts=START + timedelta(minutes=rng.randrange(450)),
                         priority=float(rng.choice((20, 30, 40, 50, 60, 70))),
                         provenance="agent" if rng.random() < 0.05 else "deterministic"))
    return rows


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_no_confirmed_or_high_finding_falls_below_a_lead_and_nothing_else_moves(monkeypatch, seed):
    rows = _random_rows(seed)
    lanes = _lanes(rows)
    _repo_before, before, entities_before = _ranked(rows, monkeypatch, full_share=10**9)
    _repo_after, after, entities_after = _ranked(rows)
    assert entities_after == entities_before                # entity evidence is untouched
    assert set(after) == set(before)
    order_before, order_after = _order(before), _order(after)
    leads = {cid for cid in after if lanes[cid] == "lead"}
    discounted = 0
    for cid in after:
        for field in ("reported", "section", "entity_kind", "entity"):
            assert after[cid][field] == before[cid][field]
        if lanes[cid] == "lead":
            assert after[cid]["score"] <= before[cid]["score"]
            discounted += after[cid]["score"] < before[cid]["score"]
        else:
            assert after[cid]["score"] == before[cid]["score"]
            # the leads above a confirmed or high finding now are a subset of those above it before
            above_now = set(order_after[:order_after.index(cid)]) & leads
            above_before = set(order_before[:order_before.index(cid)]) & leads
            assert above_now <= above_before
    assert discounted                                        # the fixture does exercise the discount


def test_the_pass_before_expansion_keeps_full_inheritance():
    """Expansion walks pass 1 in rank order and bounds its own seeds per host and per rule; its order is unchanged."""
    _repo, findings, entities = _ranked(_busy_rows(), pass_no=PASS_BEFORE_EXPANSION)
    srv = entities[("host", "srv")]["score"]
    assert {findings[f"b-admin{index}"]["score"] for index in range(8)} == {srv + 50}
    assert not any("inherits" in str(row["reasons"]) for row in findings.values())


def test_ordinals_put_deterministic_findings_first_and_stronger_lanes_before_leads():
    """An agent lead with an earlier time and a stronger prior never takes a deterministic lead's full share; a high of
    the rule takes an ordinal (its evidence is already shown at full strength) and is never discounted."""
    minute = timedelta(minutes=1)
    rows = [_row("s-exec", "r.exec", lane="high", host="s", attack=["T1059"], ts=START),
            _row("s-dump", "r.dump", lane="high", host="s", attack=["T1003"], ts=START + minute),
            _row("a-early", "r.admin", host="s", ts=START - timedelta(hours=1), priority=90, provenance="agent"),
            _row("d-high", "r.admin", lane="high", host="s", ts=START + 9 * minute, priority=20),
            *[_row(f"d{index}", "r.admin", host="s", ts=START + (2 + index) * minute) for index in range(3)]]
    _repo, findings, entities = _ranked(rows)
    srv = entities[("host", "s")]["score"]
    assert findings["d-high"]["score"] == srv + 20                     # ordinal 1, a high: full
    assert findings["d0"]["score"] == srv + 30                         # ordinal 2: full
    assert findings["d1"]["score"] == pytest.approx(srv * 2 / 3 + 30)  # ordinal 3
    assert findings["d2"]["score"] == pytest.approx(srv * 2 / 4 + 30)  # ordinal 4
    assert findings["a-early"]["score"] == pytest.approx(srv * 2 / 5 + 90)


# -- findings stored after the pass --------------------------------------------------------------------------------
def test_a_late_agent_lead_takes_its_ordinal_after_the_stored_rows_and_moves_no_stored_rank():
    rows = _busy_rows()
    repo, before, entities = _ranked(rows)
    srv = entities[("host", "srv")]["score"]
    late = [_row("z-agent", "host.account_change", host="srv", ts=START - timedelta(hours=1), priority=70,
                 provenance="agent"),
            _row("z-agent-high", "host.account_change", lane="high", host="srv", ts=START, priority=70,
                 provenance="agent")]
    _insert(repo, late)
    preview = rank_unranked(repo, "h1", late)
    place_late_findings(repo, "h1")
    after, entities_after = _ranks(repo)
    assert entities_after == entities
    fields = ("score", "reported", "section", "entity_kind", "entity", "reasons")
    assert {cid: tuple(after[cid][key] for key in fields) for cid in before} == {
        cid: tuple(row[key] for key in fields) for cid, row in before.items()}
    # the late high takes ordinal 9 at full share; the late lead ordinal 10
    assert after["z-agent-high"]["score"] == srv + 70
    assert after["z-agent"]["score"] == pytest.approx(srv * 2 / 10 + 70)
    reasons = after["z-agent"]["reasons"]
    reasons = json.loads(reasons) if isinstance(reasons, str) else reasons
    assert any(line.startswith("lead 10 of host.account_change listed under host:srv") for line in reasons)
    assert reasons[-1] == "ranked from the stored entity scores after the last ranking pass"
    assert preview["z-agent"]["score"] == pytest.approx(after["z-agent"]["score"])
    assert preview["z-agent"]["reasons"] == reasons


def test_repeat_discount_model():
    assert model.repeat_discount(lane="lead", ordinal=2, inherited=100.0, rule_id="r", entity_kind="host",
                                 entity="a") == (0.0, None)
    for lane in ("urgent", "high"):
        assert model.repeat_discount(lane=lane, ordinal=50, inherited=100.0, rule_id="r", entity_kind="host",
                                     entity="a") == (0.0, None)
    assert model.repeat_discount(lane="lead", ordinal=5, inherited=100.0, rule_id="r", entity_kind=None,
                                 entity=None) == (0.0, None)
    discount, reason = model.repeat_discount(lane="lead", ordinal=4, inherited=100.0, rule_id="r",
                                             entity_kind="host", entity="a")
    assert discount == 50.0 and reason.endswith("(-50)") and "lead 4 of r listed under host:a" in reason


# -- mission scale --------------------------------------------------------------------------------------------------
def test_one_huge_group_and_thousands_of_entities_stay_within_pages(tmp_path, monkeypatch):
    """One host with tens of thousands of leads of one rule beside three thousand other hosts: every finding is
    ranked, each page holds at most one page of rows, statements grow with pages, and the huge group's n-th lead
    inherits REPEAT_FULL_SHARE/n of its host's score."""
    from romulus.store import schema as t

    repo = _repo(tmp_path / "repeats.db")
    huge, hosts, batch_size = 30_000, 3_000, 1000
    with repo.engine.begin() as connection:
        batch = [_row("a-exec", "r.exec", lane="high", host="busy", attack=["T1059"], ts=START),
                 _row("a-dump", "r.dump", lane="high", host="busy", attack=["T1003"], ts=START)]
        for index in range(huge):
            batch.append(_row(f"b{index:06d}", "r.admin", host="busy", attack=["T1136"],
                              ts=START + timedelta(seconds=index)))
            if len(batch) >= 5000:
                connection.execute(t.candidate.insert(), batch)
                batch = []
        for index in range(hosts):
            # sixty rules, each on a twentieth of the hosts: none is recurring fleet-wide
            batch += [_row(f"o{index:05d}-{n}", f"r.net{(3 * index + n) % 60}", lane=("high", "lead", "lead")[n],
                           host=f"o{index:05d}", attack=[("T1046", "T1071", "T1041")[n]],
                           ts=START + timedelta(minutes=index % 400)) for n in range(3)]
            if len(batch) >= 5000:
                connection.execute(t.candidate.insert(), batch)
                batch = []
        connection.execute(t.candidate.insert(), batch)
    monkeypatch.setattr(model, "REPEAT_FULL_SHARE", 10**9)
    full = compute_rank_pass(repo, "h1", PASS_FINAL, batch_size=batch_size)
    monkeypatch.undo()
    summary = compute_rank_pass(repo, "h1", PASS_FINAL, batch_size=batch_size)
    total = 2 + huge + 3 * hosts
    print(json.dumps({key: summary[key] for key in ("ranked_findings", "entities", "peak_rows", "queries")}))
    assert summary["ranked_findings"] == total
    assert summary["peak_rows"] <= 2 * batch_size
    # the repeats add one read and one write per page of discounted leads, never a statement per row
    assert summary["queries"] - full["queries"] <= 2 * (huge // batch_size + 1)
    findings, entities = _ranks(repo)
    busy = entities[("host", "busy")]["score"]
    for index, ordinal in ((0, 1), (1, 2), (2, 3), (999, 1000), (huge - 1, huge)):
        share = 1.0 if ordinal <= model.REPEAT_FULL_SHARE else model.REPEAT_FULL_SHARE / ordinal
        assert findings[f"b{index:06d}"]["score"] == pytest.approx(busy * share + 30)
    order = _order(findings)
    # the busy host's highs lead; every other host's high and first leads outrank its thousandth lead
    assert order[:2] == ["a-dump", "a-exec"] or order[:2] == ["a-exec", "a-dump"]
    thousandth = order.index("b000999")
    assert all(order.index(f"o{index:05d}-{n}") < thousandth for index in range(0, hosts, 97) for n in range(3))
