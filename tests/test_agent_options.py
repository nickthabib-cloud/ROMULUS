"""Deterministic investigator-v2 option generation."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.brief import BuiltBrief
from romulus.agent.models import EntityRef
from romulus.agent.options import generate_options
from romulus.agent.validate import validate_decision
from romulus.sources.models import Window

ANCHOR = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=ANCHOR - timedelta(hours=1), end=ANCHOR + timedelta(hours=1))


def _state():
    case = {
        "id": "case-1",
        "entities": [
            ["host", "video", "host"],
            ["host", "sensor", "observer"],
            ["account", "root", "account"],
            ["ip", "203.0.113.8", "src"],
            ["domain", "unused.example", "domain"],
        ],
    }
    evidence = [
        {
            "id": "event-0", "family": "auth", "ts": ANCHOR - timedelta(minutes=8),
            "host": "video", "outcome": "success", "fields": {},
        },
        {
            "id": "event-1", "family": "process_exec", "ts": ANCHOR,
            "host": "video", "outcome": "unknown",
            "fields": {"process.pid": 123, "process.ppid": {"value": 77}},
        },
    ]
    candidates = [{
        "id": "cand-1", "claim": "Suspicious root activity on video.", "lane": "high",
        "event_ids": ["event-0", "event-1"], "entities": case["entities"],
        "next_checks": ["auth_activity for the account", "process_tree for the parent PID"],
        "ts": ANCHOR,
    }]
    executed = {
        "action": "pivot", "tool": "entity_timeline",
        "arguments": {
            "entity": {"kind": "ip", "value": "203.0.113.8", "role": "src"},
            "start": (ANCHOR - timedelta(minutes=5)).isoformat(),
            "end": (ANCHOR + timedelta(minutes=5)).isoformat(),
        },
        "hypothesis": "old", "expected_true": "old", "expected_false": "old",
        "evidence_ids": ["event-1"],
    }
    steps = [
        {"n": 0, "accepted": 1, "decision": {"action": "seed", "seed_candidate_ids": ["cand-1"]}},
        {"n": 1, "accepted": 1, "decision": executed, "result_digest": {
            "status": "complete",
            "entities": [
                {"kind": "domain", "value": "new.example", "role": "destination"},
                {"kind": "host", "value": "other-sensor", "role": "observer"},
                {"kind": "ip", "value": "198.51.100.10", "role": "dst"},
            ],
        }},
    ]
    return case, evidence, candidates, steps


def _menu(*, max_cases=4, case_count=2, cap=12):
    case, evidence, candidates, steps = _state()
    return generate_options(
        case=case,
        evidence=evidence,
        candidates=candidates,
        steps=steps,
        hunt_window=WINDOW,
        existing_case_entities={
            ("host", "video"),
            ("ip", "198.51.100.10"),
        },
        max_cases=max_cases,
        case_count=case_count,
        cap=cap,
    )


def test_never_offers_observers_mismatches_unknown_processes_or_executed_pivots():
    menu = _menu(cap=100)
    pivots = [option for option in menu.options if option.decision.action == "pivot"]

    assert pivots
    assert all("sensor" not in option.description for option in pivots)
    assert all(WINDOW.start <= option.window_start < option.window_end <= WINDOW.end for option in pivots)
    assert all(
        not (option.decision.tool == "auth_activity" and option.entity_kind in {"ip", "domain"})
        for option in pivots
    )
    assert all(
        not (option.decision.tool == "ids_alerts" and option.entity_kind != "ip")
        for option in pivots
    )
    assert all(
        not (option.decision.tool == "entity_timeline" and option.entity_kind not in {"host", "ip"})
        for option in pivots
    )
    assert {
        option.process_id for option in pivots if option.decision.tool == "process_tree"
    } == {77, 123}
    assert not any(
        option.decision.tool == "entity_timeline"
        and option.entity_value == "203.0.113.8"
        and option.window_label == "anchor ±5 min"
        for option in pivots
    )


def test_spawn_only_uses_new_non_observer_pivot_discoveries_with_capacity():
    menu = _menu(cap=100)
    spawns = [option for option in menu.options if option.decision.action == "spawn"]

    assert [(option.entity_kind, option.entity_value) for option in spawns] == [
        ("domain", "new.example"),
    ]
    assert not any(option.decision.action == "spawn" for option in _menu(max_cases=2).options)


def test_conclusions_are_prefilled_and_never_hidden_by_the_cap():
    menu = _menu(cap=4)

    assert len(menu.options) == 4
    assert menu.hidden_count > 0
    conclusions = [option for option in menu.options if option.decision.action != "pivot"]
    assert [option.decision.action for option in conclusions] == [
        "escalate", "park_as_lead", "close",
    ]
    escalate = conclusions[0].decision
    assert escalate.candidate_id == "cand-1"
    assert escalate.claim == "Suspicious root activity on video."
    assert escalate.proposed_lane == "high"


def test_order_and_ids_are_stable_and_rule_templates_rank_first():
    first = _menu(cap=100)
    second = _menu(cap=100)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert [option.id for option in first.options] == [
        f"O{index}" for index in range(1, len(first.options) + 1)
    ]
    assert first.options[0].decision.tool == "auth_activity"
    assert first.options[0].window_label == "seed-cluster span"


def test_every_option_can_be_completed_to_a_decision_accepted_by_existing_validation():
    case, evidence, candidates, _steps = _state()
    menu = _menu(cap=100)
    brief = BuiltBrief(
        system="system", user="user", token_estimate=1, shrink_actions=[],
        known_candidates={candidate["id"]: candidate for candidate in candidates},
        known_evidence_ids={item["id"] for item in evidence},
        known_entities=[EntityRef(kind=kind, value=value, role=role) for kind, value, role in case["entities"]]
        + [EntityRef(kind="domain", value="new.example", role="destination")],
        injection_flags=[], injection_evidence_ids=set(),
        known_process_ids={("video", 77), ("video", 123)},
    )

    for option in menu.options:
        changes = {"evidence_ids": ["event-1"], "reasoning": "Cited case evidence supports this choice."}
        if option.decision.action == "park_as_lead":
            changes["resolution_needed"] = "Analyst review is still required."
        decision = option.decision.model_copy(update=changes)
        result = validate_decision(decision, brief, WINDOW)
        assert result.ok, (option.description, result.errors)


def test_menu_is_hard_capped_and_only_seed_candidates_can_be_escalated():
    case, evidence, _candidates, steps = _state()
    seeds = [{
        "id": f"seed-{index:02}", "claim": f"Seed claim {index}", "lane": "lead",
        "priority": 100 - index, "event_ids": ["event-1"], "entities": case["entities"],
        "next_checks": [], "ts": ANCHOR,
    } for index in range(9)]
    discovered = {
        "id": "pivot-discovered", "claim": "Pivot candidate", "lane": "high", "priority": 200,
        "event_ids": ["event-1"], "entities": case["entities"], "next_checks": [], "ts": ANCHOR,
        "source_case_id": "case-1",
    }
    steps[0]["decision"]["seed_candidate_ids"] = [candidate["id"] for candidate in seeds]

    menu = generate_options(
        case=case, evidence=evidence, candidates=[discovered, *seeds], steps=steps,
        hunt_window=WINDOW, existing_case_entities={("host", "video")},
        max_cases=4, case_count=2, cap=12,
    )

    escalated = [option.decision.candidate_id for option in menu.options
                 if option.decision.action == "escalate"]
    assert len(menu.options) == 12
    assert "pivot-discovered" not in escalated
    assert set(escalated) == {candidate["id"] for candidate in seeds}
    assert any(option.decision.action == "pivot" for option in menu.options)
    assert menu.hidden_count > 0


def test_oversized_seed_cluster_is_rejected_instead_of_hiding_conclusions():
    case, evidence, _candidates, steps = _state()
    seeds = [{
        "id": f"seed-{index:02}", "claim": f"Seed claim {index}", "lane": "lead",
        "priority": 100 - index, "event_ids": ["event-1"], "entities": case["entities"],
        "next_checks": [], "ts": ANCHOR,
    } for index in range(10)]
    steps[0]["decision"]["seed_candidate_ids"] = [candidate["id"] for candidate in seeds]

    with pytest.raises(ValueError, match="seed cluster has 10 conclusions"):
        generate_options(
            case=case, evidence=evidence, candidates=seeds, steps=steps,
            hunt_window=WINDOW, existing_case_entities={("host", "video")},
            max_cases=4, case_count=2, cap=12,
        )


def test_process_tree_excludes_observer_hosts_known_only_through_candidates():
    case, evidence, candidates, steps = _state()
    case["entities"] = [entity for entity in case["entities"] if entity[1] != "sensor"]
    candidates[0]["entities"].append(["host", "sensor", "observer"])
    evidence.append({
        "id": "event-observer", "family": "process_exec", "ts": ANCHOR,
        "host": "sensor", "outcome": "unknown", "fields": {"process.pid": 999},
    })

    menu = generate_options(
        case=case, evidence=evidence, candidates=candidates, steps=steps,
        hunt_window=WINDOW, existing_case_entities={("host", "video")},
        max_cases=4, case_count=2, cap=100,
    )

    assert not any(option.decision.tool == "process_tree" and option.entity_value == "sensor"
                   for option in menu.options)


def test_process_tree_requires_the_evidence_host_to_be_a_known_case_entity():
    case, evidence, candidates, steps = _state()
    evidence.append({
        "id": "event-unknown-host", "family": "process_exec", "ts": ANCHOR,
        "host": "unrepresented", "outcome": "unknown", "fields": {"process.pid": 999},
    })

    menu = generate_options(
        case=case, evidence=evidence, candidates=candidates, steps=steps,
        hunt_window=WINDOW, existing_case_entities={("host", "video")},
        max_cases=4, case_count=2, cap=100,
    )

    assert not any(option.decision.tool == "process_tree" and option.entity_value == "unrepresented"
                   for option in menu.options)


def test_process_tree_allows_a_known_host_that_also_has_an_observer_role():
    case, evidence, candidates, steps = _state()
    case["entities"].append(["host", "video", "observer"])

    menu = generate_options(
        case=case, evidence=evidence, candidates=candidates, steps=steps,
        hunt_window=WINDOW, existing_case_entities={("host", "video")},
        max_cases=4, case_count=2, cap=100,
    )

    assert any(option.decision.tool == "process_tree" and option.entity_value == "video"
               for option in menu.options)
