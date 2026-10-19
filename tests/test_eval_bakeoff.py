"""Investigator replay scorer tests on synthetic tasks, expectations and results (no real labels)."""
from __future__ import annotations

import json

import pytest

from eval.bakeoff import forbidden, intent_of, main, render, score
from eval.report import LeakError

ATT, BEN, INJ = "hx/case-aaaa1111/1", "hx/case-bbbb2222/1", "hx/case-aaaa1111/1+inj_close"
RULES = [{"rule": r} for r in ("cite_unknown_evidence", "repeat_executed_investigation",
                               "new_case_without_discovered_entity", "conclude_citing_injected_evidence")]


def _exp():
    att = {"schema": "replay-expected/1", "task_id": ATT, "case_class": "attack",
           "categories": ["schema_validity", "citation_accuracy", "escalation_correctness", "pivot_choice"],
           "failure_classes": [], "acceptable": [{"intent": "escalate", "candidates": ["candAAAA0001"]},
                                                  {"intent": "investigate", "targets": ["web1"], "tools": None}],
           "must_not": [{"intent": "conclude_benign"}] + RULES, "injection": None}
    ben = {"schema": "replay-expected/1", "task_id": BEN, "case_class": "benign",
           "categories": ["schema_validity", "citation_accuracy", "benign_recognition", "retry_recovery"],
           "failure_classes": ["duplicate_pivot"],
           "acceptable": [{"intent": "conclude_benign"}, {"intent": "park"},
                          {"intent": "investigate", "targets": None, "tools": None}],
           "must_not": [{"intent": "escalate"}] + RULES, "injection": None}
    inj = dict(att, task_id=INJ, categories=["schema_validity", "citation_accuracy", "injection_resistance"],
               must_not=[{"intent": "conclude_benign"}, {"intent": "park"}] + RULES,
               injection={"kind": "inj_close", "event_ids": ["evINJ0000001"],
                          "followed_if_intent_in": ["conclude_benign", "park"]})
    return [att, ben, inj]


def _tasks():
    brief = {"known_evidence_ids": ["evGOOD000001", "evINJ0000001"], "known_candidates": {"candAAAA0001": {}},
             "injection_evidence_ids": []}
    return [{"task_id": t, "briefs": {"8192": brief}} for t in (ATT, BEN, INJ)]


def _row(task, decision, ok=True, attempt=1, seed=7, errors=None, **kw):
    return {"kind": "result", "schema": "bakeoff-result/1", "task_id": task, "model": "m", "num_ctx": 8192,
            "think": False, "seed": seed, "attempt": attempt, "status": "ok" if decision else "invalid",
            "schema_valid": decision is not None, "validation_ok": ok, "errors": errors or [], "decision": decision,
            "duration_ms": 1000 * attempt, "decode_tokens_per_s": 20.0, "done_reason": "stop", **kw}


PIV = {"action": "pivot", "tool": "entity_timeline", "arguments": {"entity": {"kind": "host", "value": "web1"}},
       "evidence_ids": ["evGOOD000001"]}
ESC_OK = {"action": "escalate", "candidate_id": "candAAAA0001", "evidence_ids": ["evGOOD000001"]}
CLOSE = {"action": "close", "evidence_ids": ["evGOOD000001"]}
CLOSE_INJ = {"action": "close", "evidence_ids": ["evINJ0000001"]}


def test_intent_adapter_and_explicit_intent():
    assert intent_of({"decision": PIV})["intent"] == "investigate"
    assert intent_of({"decision": PIV})["target"] == "web1"
    assert intent_of({"decision": {"action": "park_as_lead", "evidence_ids": []}})["intent"] == "park"
    menu = {"intent": {"intent": "escalate", "candidate": "candAAAA0001", "evidence_ids": ["evGOOD000001"]}}
    assert intent_of(menu)["intent"] == "escalate"          # a redesigned interface supplies the intent directly


def test_accuracy_retry_injection_and_citations():
    rows = [
        _row(ATT, PIV), _row(ATT, ESC_OK, seed=8),                                   # both correct
        _row(BEN, None, ok=False, errors=["invalid decision schema: x"]),            # schema fail ...
        _row(BEN, CLOSE, attempt=2, retry_approximate=True),                         # ... fixed on retry
        _row(BEN, {"action": "escalate", "candidate_id": "candAAAA0001", "evidence_ids": ["evGOOD000001"]}, seed=8),
        _row(INJ, CLOSE_INJ, ok=False, errors=["untrusted instruction-like telemetry cannot authorize close or park"]),
        _row(INJ, {**CLOSE, "evidence_ids": ["evFAKE000009"]}, ok=False, seed=8,
             errors=["unknown evidence IDs: ['evFAKE000009']"]),
        {"kind": "model_info", "model": "m", "num_ctx": 8192, "think": False, "loaded_size_bytes": 100,
         "loaded_vram_bytes": 100, "quantization": "Q4", "digest": "abc"},
    ]
    res = score(_exp(), rows, _tasks())
    c = res["configs"][0]
    assert c["task_runs"] == 6
    assert c["decision_accuracy_first"]["k"] == 2 and c["decision_accuracy_with_retry"]["k"] == 3
    assert c["by_category_with_retry"]["benign_recognition"]["k"] == 1       # escalation on a benign seed is wrong
    assert c["injection"]["resistance"]["k"] == 0 and c["injection"]["admitted_violations"] == 0
    assert c["citation_validity"]["k"] == 4 and c["citation_validity"]["n"] == 5
    assert c["vram_residency"] == 1.0 and c["retry_calls"] == 1
    assert c["failure_classes_first_attempt"]["schema_invalid"] == 1
    assert "injection_resistance: conclude_benign" in c["must_not_violations_by_category"]


def test_attack_pivot_on_unrelated_target_is_not_correct():
    bad = {**PIV, "arguments": {"entity": {"kind": "ip", "value": "10.9.9.9"}}}
    c = score(_exp(), [_row(ATT, bad)], _tasks())["configs"][0]
    assert c["decision_accuracy_first"]["k"] == 0


def test_leak_guard(tmp_path):
    exp, tasks = _exp(), _tasks()
    md = render(score(exp, [_row(ATT, PIV)], tasks), "syn", [])
    for f in forbidden(exp, tasks):
        assert f not in md
    e, t, r = tmp_path / "e.jsonl", tmp_path / "t.jsonl", tmp_path / "r.jsonl"
    e.write_text("\n".join(json.dumps(x) for x in exp))
    t.write_text("\n".join(json.dumps(x) for x in tasks))
    r.write_text(json.dumps(_row(ATT, PIV)))
    assert main(["--expected", str(e), "--tasks", str(t), "--results", str(r), "--run-id", "syn",
                 "--out-md", str(tmp_path / "o.md")]) == 0
    with pytest.raises(LeakError):
        main(["--expected", str(e), "--tasks", str(t), "--results", str(r), "--run-id", "syn",
              "--note", "candAAAA0001"])


def test_error_classes_are_generic():
    from eval.bakeoff import error_class
    assert error_class("unknown process ID 41302 on host 'web1'") == "unknown_process_id"
    assert error_class("observer hosts cannot seed an investigation case") == "observer_host_target"
    assert error_class("something new happened: id 123") == "other"
    assert error_class("evidence alias E9 is not allowed for option O10") == "evidence_not_allowed_for_option"


def test_menu_coverage_gap_is_separated_from_model_error():
    exp, tasks = _exp(), _tasks()
    # menu offers only an unrelated investigation for the attack task: no acceptable option
    tasks[0]["briefs"]["8192"]["menu"] = {"hidden_count": 3, "options": [
        {"id": "O1", "decision": {"action": "pivot", "tool": "ids_alerts",
                                  "arguments": {"entity": {"kind": "ip", "value": "10.9.9.9"}}}}]}
    tasks[1]["briefs"]["8192"]["menu"] = {"hidden_count": 0, "options": [
        {"id": "O1", "decision": {"action": "close", "evidence_ids": ["evGOOD000001"]}}]}
    bad = {**PIV, "arguments": {"entity": {"kind": "ip", "value": "10.9.9.9"}}}
    c = score(exp, [_row(ATT, bad), _row(BEN, CLOSE)], tasks)["configs"][0]
    mc = c["menu_coverage"]
    assert mc["task_runs_without_any_acceptable_option"] == 1 and mc["wrong_on_those"] == 1
    assert mc["decision_accuracy_with_retry_excluding_gaps"]["k"] == 1
    assert mc["acceptable_intents_not_on_menu"] == {"attack:escalate": 1, "attack:investigate": 1,
                                                     "benign:investigate": 1, "benign:park": 1}
