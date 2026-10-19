"""Evaluation harness tests. Synthetic gold and a synthetic hunt DB built from the real store schema.

Nothing here is a real label or locator: indices, ids, hosts and addresses are invented.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine

from eval import funnel as funnel_mod
from eval import metrics as M
from eval.gold import load, locator_key
from eval.hunt import connect_ro, load_hunt
from eval.match import match_all
from eval.report import LeakError, render
from eval.score import score, write_outputs
from romulus.store import schema as t
from romulus.store.repo import raw_id

HIDX, NIDX = "syn-host-index", "syn-net-index"
D = "2030-01-01"


def ts(hms: str) -> datetime:
    return datetime.fromisoformat(f"{D}T{hms}+00:00")


def iso(hms: str) -> str:
    return f"{D}T{hms}Z"


def opp(oid, klass, sev, obs, start, end, ents, sources, attack=("T1190",), derived=False, reason=None, pos="middle"):
    return {"schema": "gold-opportunity/1", "dataset": "synthetic", "opp_id": oid, "title": "synthetic",
            "behavior_class": klass, "severity": sev, "attack": list(attack), "attackmate_actions": [],
            "derived_from": ["OPPX"] if derived else [], "entities": ents,
            "window_utc": {"start": iso(start) if start else None, "end": iso(end) if end else None},
            "sources": {s: {"status": sources.get(s, "none")} for s in ("host_index", "network_index", "arkime", "pcap")},
            "observability": obs, "not_observable_reason": reason, "note": None,
            "time_position": {"hunt_window": pos}}


def es_row(oid, src, role, index, did, hms, ds):
    return {"schema": "gold-opportunity/1", "opp_id": oid, "source": src, "role": role, "kind": "es",
            "index": index, "id": did, "ts": iso(hms), "dataset": ds}


@pytest.fixture()
def gold_dir(tmp_path):
    d = tmp_path / "gold"
    d.mkdir()
    opps = [
        opp("OPP01", "exploit_public_app", "critical", "observable", "12:00:00", "12:00:10",
            {"hosts": ["web1"], "accounts": ["svc"]}, {"host_index": "direct"}),
        opp("OPP02", "c2_channel", "high", "observable", "12:05:00", "12:06:00",
            {"ips": ["10.0.0.5", "203.0.113.9"]}, {"network_index": "direct"}, attack=("T1571",), pos="late"),
        opp("OPP03", "discovery", "low", "observable", "13:00:00", "13:00:01", {"hosts": ["web1"]},
            {"host_index": "direct"}, attack=("T1082",), pos="late"),
        opp("OPP04", "staging", "low", "not_observable", None, None, {"hosts": ["attacker"]}, {},
            reason="attacker_host_logs_not_loaded"),
        opp("OPP05", "tool_transfer", "high", "inferable_only", "12:02:00", "12:02:05", {"hosts": ["web1"]},
            {"host_index": "indirect"}, attack=("T1105",)),
        opp("OPP06", "discovery", "low", "observable", "13:10:00", "13:10:01", {"hosts": ["web1"]},
            {"host_index": "direct"}, attack=("T1082",), pos="late"),
    ]
    ev = [
        es_row("OPP01", "host_index", "action", HIDX, "docA0001", "12:00:02", "linux.audit"),
        es_row("OPP01", "host_index", "outcome", HIDX, "docA0002", "12:00:05", "linux.audit"),
        es_row("OPP01", "host_index", "context", HIDX, "docA0003", "12:00:06", "systemd.journal"),
        es_row("OPP02", "network_index", "action", NIDX, "docN0001", "12:09:00", "suricata.eve.flow"),
        es_row("OPP03", "host_index", "action", HIDX, "docD0001", "13:00:00", "linux.audit"),
        es_row("OPP05", "host_index", "indirect", HIDX, "docT0001", "12:10:00", "linux.audit"),
        es_row("OPP06", "host_index", "action", HIDX, "docF0001", "13:10:00", "linux.audit"),
    ]
    (d / "gold_opportunities.v1.jsonl").write_text("\n".join(json.dumps(o) for o in opps) + "\n")
    (d / "gold_evidence.v1.jsonl").write_text("\n".join(json.dumps(r) for r in ev) + "\n")
    (d / "aliases.v1.json").write_text(json.dumps({"hosts": {"web1": ["10.0.0.5"]}}))
    return d


PACK = {"version": "syn-pack@1", "playbooks": [
    {"id": "rule.exec", "families": ["process_exec"], "attack": ["T1190", "T1082"], "assures_negative": False},
    {"id": "rule.flow", "families": ["net_flow"], "attack": ["T1571"], "assures_negative": True}]}


def _event(eid, family, hms, host, target, native, fields=None):
    return {"id": eid, "hunt_id": "H-OLD", "family": family, "ts": ts(hms), "host": host,
            "event": {"id": eid, "family": family, "ts": iso(hms), "host": host, "fields": fields or {},
                      "raw": [{"target": target, "native_id": native, "digest": "d-" + native}]},
            "raw_ids": [raw_id(target, native)], "normalizer": "lab-ecs@1"}


def _cand(cid, lane, prio, eids, ents, hms, rule="rule.exec", created="09:00:30", pf=None):
    return {"id": cid, "hunt_id": "H1", "rule_id": rule, "rule_version": "1", "claim": "synthetic claim",
            "claim_type": "observed_action", "event_ids": eids, "predicate_fields": pf or [],
            "entities": ents, "ts": ts(hms), "severity": "high", "confidence": "high", "lane": lane,
            "priority": prio, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
            "next_checks": [], "source_case_id": None, "created_at": datetime.fromisoformat(f"2040-01-01T{created}+00:00")}


@pytest.fixture()
def hunt_db(tmp_path):
    p = tmp_path / "hunt.db"
    eng = create_engine(f"sqlite:///{p}")
    t.metadata.create_all(eng)
    now = datetime(2040, 1, 1, 9, 0, tzinfo=UTC)
    manifest = {"window": {"start": iso("10:00:00"), "end": iso("17:30:00")}, "pack": PACK, "normalizer": "lab-ecs@1",
                "policy": "decide@1", "model": {"triage": "m"}, "config_digest": "cfg", "targets": [HIDX, NIDX]}
    with eng.begin() as c:
        c.execute(t.hunt.insert().values(id="H-OLD", created_at=now, created_by="x", manifest={}, manifest_digest="o",
                                         execution_state="completed_within_scope"))
        c.execute(t.hunt.insert().values(id="H1", created_at=now, created_by="x", manifest=manifest, manifest_digest="m",
                                         execution_state="completed_within_scope", detection_result="reportable_findings",
                                         started_at=now, ended_at=datetime(2040, 1, 1, 9, 2, tzinfo=UTC)))
        for tid, target, ds, state, comp in (("t1", HIDX, ["linux.audit"], "evaluated", "complete"),
                                              ("t2", NIDX, ["suricata.eve.flow"], "evaluated", "complete")):
            c.execute(t.task.insert().values(
                id=tid, hunt_id="H1", kind="sweep", owner="sweep", fingerprint=tid, state=state, priority=0.0,
                attempts=1, created_at=now, updated_at=now, outcome={"completeness": comp, "returned": 10, "total": 10},
                intent={"kind": "raw", "target": target, "window": {"start": iso("10:00:00"), "end": iso("17:30:00")},
                        "filters": [{"field": "event.dataset", "op": "in", "value": ds}]}))
        evs = [_event("e1", "process_exec", "12:00:02", "web1", HIDX, "docA0001",
                      {"process.user": {"value": "svc", "origin": "docA0001:event.original#x"}}),
               _event("e2", "net_flow", "12:09:00", None, NIDX, "docN0001",
                      {"flow.start": {"value": iso("12:05:30"), "origin": "docN0001:x"},
                       "flow.end": {"value": iso("12:05:40"), "origin": "docN0001:x"}}),
               _event("e3", "process_exec", "12:00:06", "web1", HIDX, "docA0003"),
               _event("e4", "process_exec", "13:00:00", "web1", HIDX, "docZ9999"),
               _event("e5", "process_exec", "13:00:00", "web1", HIDX, "docD0001"),
               _event("e6", "process_exec", "15:00:00", "otherhost", HIDX, "docA0001")]
        # e6 re-cites docA0001 with a different host and time: a locator-match anomaly
        evs[-1]["id"] = "e6"
        evs[-1]["event"]["id"] = "e6"
        c.execute(t.typed_event.insert(), evs)
        raws = {(e["event"]["raw"][0]["target"], e["event"]["raw"][0]["native_id"]) for e in evs}
        c.execute(t.raw_record.insert(), [{"id": raw_id(a, b), "target": a, "native_id": b, "digest": "d-" + b,
                                            "source": {}, "first_task_id": None, "retrieved_at": now} for a, b in raws])
        c.execute(t.candidate.insert(), [
            _cand("c1", "urgent", 90, ["e1"], [["host", "web1", "host"]], "12:00:02", created="09:00:40",
                  pf=[{"field": "process.user", "value": "svc", "origin": "docA0001:event.original#x"}]),
            _cand("c2", "lead", 40, ["e2"], [["ip", "203.0.113.9", "dst"]], "12:09:00", rule="rule.flow"),
            _cand("c3", "high", 70, ["e3"], [["host", "web1", "host"]], "12:00:06"),
            _cand("c4", "lead", 30, ["e4"], [["host", "web1", "host"]], "13:00:00"),
            _cand("c5", "context", 5, ["e5"], [["host", "web1", "host"]], "13:00:00"),
            _cand("c6", "high", 60, ["e6"], [["host", "otherhost", "host"]], "15:00:00"),
        ])
        c.execute(t.rule_run.insert(), [
            {"hunt_id": "H1", "rule_id": "rule.exec", "rule_version": "1", "target": HIDX,
             "partition": "2030-01-01T13:00:00+00:00/2030-01-01T14:00:00+00:00", "state": "no_match_complete",
             "matched": 0, "evaluated": 5, "detail": {}},
            {"hunt_id": "H1", "rule_id": "rule.exec", "rule_version": "1", "target": HIDX,
             "partition": "2030-01-01T11:00:00+00:00/2030-01-01T12:30:00+00:00", "state": "evaluated_complete",
             "matched": 0, "evaluated": 5, "detail": {}}])
        c.execute(t.audit_event.insert().values(at=now, actor="x", action="hunt.agent_summary", hunt_id="H1",
                                                detail={"status": "disabled"}))
    eng.dispose()
    return p


def _scored(gold_dir, hunt_db, **kw):
    return score(gold_dir, hunt_db, "H1", "synthetic-run", **kw)


def test_wilson():
    assert M.wilson(0, 0)["p"] is None
    w = M.wilson(5, 10)
    assert w["p"] == 0.5 and abs(w["lo"] - 0.2366) < 1e-3 and abs(w["hi"] - 0.7634) < 1e-3


def test_db_is_opened_read_only(hunt_db):
    conn = connect_ro(hunt_db)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM candidate")
    conn.close()


def test_recall_lanes_and_denominators(gold_dir, hunt_db):
    r, _, _ = _scored(gold_dir, hunt_db)
    rec = r["recall"]
    # observable: OPP01, OPP02, OPP03, OPP06; reported hits OPP01 only; surfaced adds OPP02 (lead)
    assert rec["reported"]["all_observable"]["k"] == 1 and rec["reported"]["all_observable"]["n"] == 4
    assert rec["surfaced"]["all_observable"]["k"] == 2
    assert rec["reported"]["critical_high"] == M.wilson(1, 2)
    assert rec["surfaced"]["by_source"]["network_index"]["k"] == 1
    assert rec["reported"]["by_source"]["network_index"]["k"] == 0
    assert rec["not_observable"]["count"] == 1 and rec["mentioned_only"] == 1      # OPP03 only in context
    assert rec["inferable_only"]["surfaced"]["n"] == 1


def test_flow_interval_drives_time_match(gold_dir, hunt_db):
    g = load(gold_dir)
    conn = connect_ro(hunt_db)
    h = load_hunt(conn, "H1")
    conn.close()
    c2 = next(i for i in h.items if i.id == "c2")
    assert c2.t_min.isoformat().startswith(f"{D}T12:05:30")   # logged at 12:09, flow started 12:05:30
    m = match_all([c2], g)[0]
    assert m.tier_a == {"OPP02"}


def test_tier_b_and_anomaly(gold_dir, hunt_db):
    g = load(gold_dir)
    conn = connect_ro(hunt_db)
    h = load_hunt(conn, "H1")
    conn.close()
    by = {m.item.id: m for m in match_all(h.items, g)}
    assert by["c3"].tier_a == set() and "OPP01" in by["c3"].tier_b and "OPP01" in by["c3"].context_only
    assert by["c4"].tier_b >= {"OPP03"} and not by["c4"].tier_a
    assert by["c6"].tier_a == set() and by["c6"].anomalies and by["c6"].anomalies[0][0] == "OPP01"


def test_precision_bounds_and_adjudication(gold_dir, hunt_db, tmp_path):
    r, priv, _ = _scored(gold_dir, hunt_db)
    p10 = r["precision"]["p10"]
    assert p10["n_reviewed"] == 5 and p10["tp"] == 2 and p10["unadjudicated"] == 3 and p10["p"] is None
    assert p10["p_lower"] == 0.4 and p10["p_upper"] == 1.0
    adj = tmp_path / "adj.jsonl"
    adj.write_text("\n".join(json.dumps({"signature": u["signature"], "verdict": "benign"})
                             for u in priv["unadjudicated"]) + "\n")
    r2, _, _ = _scored(gold_dir, hunt_db, adjudications=adj)
    assert r2["precision"]["p10"]["p"] == 0.4
    fl = r2["false_leads"]
    assert fl["false"] == 3 and fl["per_hour"] == round(3 / (5 * 5 / 60), 2)
    br = r2["precision"]["by_rule"]
    assert br["rule.exec"]["n"] == 4 and br["rule.exec"]["benign"] == 3 and br["rule.exec"]["tier_a_hit"] == 1
    assert br["rule.flow"] == {"n": 1, "tier_a_hit": 1, "lane:lead": 1}


def test_funnel_without_and_with_replay(gold_dir, hunt_db):
    _r, priv, _ = _scored(gold_dir, hunt_db)
    per = priv["per_opportunity"]
    assert per["OPP06"]["funnel"]["stage"] == "retrieved"          # complete covering task, no replay
    assert per["OPP03"]["funnel"]["stage"] == "candidate"          # cited only by a context item

    class Ref:
        def __init__(self, target, nid):
            self.target, self.native_id = target, nid

    class Ev:
        def __init__(self, hit):
            self.family, self.ts = "process_exec", ts("13:10:00")
            self.raw = [Ref(hit["_index"], hit["_id"])]

    def fetcher(index, ids):
        return [{"_index": index, "_id": i, "_source": {}} for i in ids]

    def normalize(hits):
        return [Ev(h) for h in hits], {}, []
    r2, priv2, _ = _scored(gold_dir, hunt_db, fetcher=fetcher, normalize=normalize)
    assert priv2["per_opportunity"]["OPP06"]["funnel"]["stage"] == "evaluated"
    assert sum(r2["funnel"]["by_stage"].values()) == r2["funnel"]["misses"] == 3


def test_coverage_claim_candidates(gold_dir, hunt_db):
    r, _, _ = _scored(gold_dir, hunt_db)
    # only the no_match_complete cell counts (OPP03 and OPP06); the evaluated_complete cell holding OPP01 does not
    assert r["coverage_claims"]["candidate_false_complete_negatives"] == 2
    assert r["coverage_claims"]["complete_negative_cells"] == 1


def test_citation_checks(gold_dir, hunt_db):
    r, _, _ = _scored(gold_dir, hunt_db)
    c = r["citations"]
    assert c["reported_items"] == 3 and c["retained_digest_match"]["k"] == 3
    assert c["predicate_origin_in_citations"] == M.wilson(1, 1)


def test_leak_guard_and_private_output(gold_dir, hunt_db, tmp_path):
    r, priv, g = _scored(gold_dir, hunt_db)
    forbidden = g.forbidden_strings()
    md = write_outputs(r, priv, forbidden, out_md=tmp_path / "r.md", out_json=tmp_path / "r.json")
    for f in forbidden:
        assert f not in md
    r["notes"] = ["see docA0001"]
    with pytest.raises(LeakError):
        write_outputs(r, priv, forbidden)
    r["notes"] = []
    from eval.score import REPO_ROOT
    with pytest.raises(PermissionError):
        write_outputs(r, priv, forbidden, private_out=REPO_ROOT / "eval" / "leak.json")
    assert not (REPO_ROOT / "eval" / "leak.json").exists()


def test_holdout_mode_drops_class_breakdowns(gold_dir, hunt_db):
    r, _, _ = _scored(gold_dir, hunt_db, mode="holdout")
    assert "by_stage_class" not in r["funnel"] and "by_class" not in r["recall"]["reported"]
    assert "Behavior class" not in render(r)


def test_locator_key_forms():
    assert locator_key("es", "i", "x") == ("es", "i", "x")
    assert locator_key("pcap", "f", "7") == ("pcap", "f", 7)
    assert funnel_mod.STAGES[0] == "source" and funnel_mod.STAGES[-1] == "reported"


@pytest.fixture()
def agent_db(hunt_db):
    """Adds model-on hunt H2: one sweep item, one case with an executed pivot that retrieves a gold record."""
    eng = create_engine(f"sqlite:///{hunt_db}")
    now = datetime(2040, 1, 1, 9, 0, tzinfo=UTC)
    with eng.begin() as c:
        man = dict(c.execute(t.hunt.select().where(t.hunt.c.id == "H1")).mappings().one()["manifest"])
        c.execute(t.hunt.insert().values(id="H2", created_at=now, created_by="x", manifest=man, manifest_digest="m",
                                         execution_state="completed_within_scope", detection_result="reportable_findings",
                                         started_at=now, ended_at=datetime(2040, 1, 1, 9, 5, tzinfo=UTC)))
        cand = _cand("k1", "urgent", 90, ["e1"], [["host", "web1", "host"]], "12:00:02", created="09:00:20")
        cand["hunt_id"] = "H2"
        c.execute(t.candidate.insert(), [cand])
        c.execute(t.task.insert().values(
            id="tp1", hunt_id="H2", kind="pivot", owner="case-1", fingerprint="tp1", state="evaluated", priority=0.0,
            attempts=1, created_at=now, updated_at=now, outcome={"completeness": "complete", "returned": 1, "total": 1},
            intent={"kind": "raw", "target": HIDX, "window": {"start": iso("13:00:00"), "end": iso("13:30:00")}}))
        c.execute(t.raw_record.insert().values(id=raw_id(HIDX, "docF0001"), target=HIDX, native_id="docF0001",
                                               digest="d-docF0001", source={}, first_task_id="tp1", retrieved_at=now))
        c.execute(t.case.insert().values(id="case-1", hunt_id="H2", title="x", status="fallback_parked", priority=1.0,
                                         entities=[{"kind": "host", "value": "web1", "role": "host"}], hypotheses=[],
                                         steps_used=3, step_budget=8, created_at=now, updated_at=now,
                                         summary=json.dumps({"model_conclusion": "deterministic_fallback_park",
                                                             "analyst_flag": {"reason": "validation_fallback"}})))
        steps = [(0, {"action": "seed", "seed_candidate_ids": ["k1"]}, 1, None, None),
                 (1, {"action": "pivot", "tool": "entity_timeline",
                      "arguments": {"entity": {"kind": "host", "value": "web1"}}}, 1, None,
                  {"status": "complete", "task_ids": ["tp1"], "event_ids": []}),
                 (2, {"action": "pivot", "tool": "entity_timeline", "arguments": {}}, 0,
                  "duplicate pivot: normalized request already executed at step 1", None),
                 (3, {"action": "close"}, 0, "unknown evidence IDs: ['zzz']", None)]
        for n, dec, acc, rej, res in steps:
            c.execute(t.case_step.insert().values(case_id="case-1", n=n, decision=dec, accepted=acc, rejection=rej,
                                                  result_digest=res, at=now))
        c.execute(t.model_call.insert(), [
            {"id": f"mc{i}", "hunt_id": "H2", "case_id": "case-1", "purpose": "triage", "model": "m", "options": {},
             "prompt_digest": "p", "prompt_eval_count": 100, "eval_count": 10, "duration_ms": 1000,
             "status": st, "at": now} for i, st in enumerate(("ok", "invalid", "ok"))])
        c.execute(t.audit_event.insert().values(at=now, actor="x", action="hunt.agent_summary", hunt_id="H2",
                                                detail={"status": "budget_exhausted", "seed_count": 1,
                                                        "concluded_seed_ids": [], "assigned_unfinished_seed_ids": ["k1"],
                                                        "unassigned_seed_ids": [], "unworked_count": 1}))
    eng.dispose()
    return hunt_db


def test_agent_effectiveness(gold_dir, agent_db):
    r, priv, _ = score(gold_dir, agent_db, "H2", "syn-on")
    a = r["agent"]
    assert a["present"] and a["cases"] == 1 and a["fallback_parked"] == 1 and a["analyst_flags"] == 1
    assert a["pivots"]["executed"] == 1 and a["pivots"]["complete"] == 1 and a["pivots"]["rejected"] == 1
    assert a["model_calls"]["total"] == 3 and a["model_calls"]["prompt_tokens"] == 300
    assert a["seeds"]["unworked"] == 1 and a["seeds"]["assigned_unfinished"] == 1
    assert a["pivot_reach"]["locator_level_opps"] == 1                    # the pivot retrieved a gold action record
    assert a["pivot_reach"]["locator_level_not_otherwise_surfaced"] == {"discovery": 1}
    assert all("zzz" not in k for k in a["rejection_reasons"])               # ids stripped from reason classes
    assert not r["hunt"]["model_off"]
    assert "Agent effectiveness" in render(r)
    assert priv["agent"]["pivot_reach_locator"] == ["OPP06"]


def test_ablation_counts_by_class(gold_dir, agent_db):
    from eval.report import ablation
    g = load(gold_dir)
    off, offp, _ = score(gold_dir, agent_db, "H1", "syn-off")
    on, onp, _ = score(gold_dir, agent_db, "H2", "syn-on")
    md = ablation(off, on, offp, onp, {o.opp_id: o.behavior_class for o in g.opportunities.values()})
    assert "| surfaced, model-off only | 1 | {'c2_channel': 1} |" in md
    assert "| reported, model-on only | 0 | {} |" in md
    for f in g.forbidden_strings():
        assert f not in md


def test_v2_menu_conclusions_and_nway_ablation(gold_dir, agent_db):
    from eval.report import ablation_n, render
    eng = create_engine(f"sqlite:///{agent_db}")
    now = datetime(2040, 1, 1, 9, 1, tzinfo=UTC)
    with eng.begin() as c:
        c.execute(t.case.insert().values(id="case-2", hunt_id="H2", title="x", status="escalated", priority=1.0,
                                         entities=[{"kind": "host", "value": "web1", "role": "host"}], hypotheses=[],
                                         steps_used=1, step_budget=8, created_at=now, updated_at=now,
                                         summary=json.dumps({"model_conclusion": "escalate"})))
        esc = {"action": "escalate", "candidate_id": "k1", "chosen_option": "O2", "deterministic_fallback": False,
               "model_attempt": 1, "menu_hidden_count": 1, "text_truncated": False,
               "menu": [{"id": "O1", "decision": {"action": "pivot", "tool": "entity_timeline"}},
                        {"id": "O2", "decision": {"action": "escalate", "candidate_id": "k1"}}]}
        c.execute(t.case_step.insert(), [
            {"case_id": "case-2", "n": 0, "decision": {"action": "seed", "seed_candidate_ids": ["k1"]}, "accepted": 1,
             "at": now},
            {"case_id": "case-2", "n": 1, "decision": esc, "accepted": 1, "at": now},
            {"case_id": "case-2", "n": 2, "decision": {"action": "constraint_defect"}, "accepted": 0, "at": now}])
    eng.dispose()
    g = load(gold_dir)
    off, offp, _ = score(gold_dir, agent_db, "H1", "syn-off")
    on, onp, _ = score(gold_dir, agent_db, "H2", "syn-on")
    a = on["agent"]
    assert a["menu"]["options_chosen_by_kind"] == {"escalate": 1} and a["menu"]["constraint_defects"] == 1
    assert a["conclusions_vs_gold"]["cases_by_status_and_gold"] == {"escalated:gold": 1}
    assert a["conclusions_vs_gold"]["escalations_on_gold_by_class"] == {"exploit_public_app": 1}
    assert "Menu decisions" in render(on)
    md = ablation_n(("off", off, offp), [("det", on, onp), ("model", on, onp)],
                    {o.opp_id: o.behavior_class for o in g.opportunities.values()})
    assert "| Metric | off | det | model |" in md and "| surfaced, off only (not det) | 1 | {'c2_channel': 1} |" in md


def test_arkime_api_id_and_es_id_canonicalize_to_same_key():
    from eval.hunt import target_to_key
    assert locator_key("arkime", "3@241118-abcDEF") == ("arkime", "241118-abcDEF")
    assert target_to_key("arkime_sessions3-241118", "241118-abcDEF") == locator_key("arkime", "3@241118-abcDEF")
