"""Per-call constrained schemas and exact investigator-v2 resolution."""
from datetime import UTC, datetime, timedelta

from romulus.agent.brief import BuiltBrief
from romulus.agent.constraints import SCHEMA_FORM, build_output_schema, eligible_evidence_aliases
from romulus.agent.models import AgentDecision, EntityRef
from romulus.agent.options import Menu, MenuOption
from romulus.agent.resolver import resolve_output
from romulus.sources.models import Window

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(hours=1))


def _menu() -> Menu:
    return Menu(options=[
        MenuOption(
            id="O1", description="entity timeline for video",
            decision=AgentDecision(
                action="pivot", tool="entity_timeline",
                arguments={
                    "entity": {"kind": "host", "value": "video", "role": "host"},
                    "start": START, "end": START + timedelta(minutes=10),
                },
                hypothesis="Related events exist.", expected_true="Events are returned.",
                expected_false="No events are returned.",
            ),
        ),
        MenuOption(
            id="O2", description="escalate candidate",
            decision=AgentDecision(
                action="escalate", candidate_id="cand-1", claim="Suspicious action.",
                proposed_lane="high",
            ),
        ),
        MenuOption(
            id="O3", description="park this case as a lead",
            decision=AgentDecision(
                action="park_as_lead", resolution_needed="Analyst review is still required.",
            ),
        ),
        MenuOption(id="O4", description="close this case", decision=AgentDecision(action="close")),
    ], hidden_count=2)


def _brief() -> BuiltBrief:
    menu = _menu()
    aliases = {
        "evidence": {"E1": "event-safe", "E2": "event-hostile"},
        "entities": {"N1": {"kind": "host", "value": "video", "role": "host"}},
        "candidates": {"C1": "cand-1"},
    }
    candidates = {
        "cand-1": {
            "id": "cand-1", "claim": "Suspicious action.", "lane": "high",
            "event_ids": ["event-hostile"],
        },
    }
    schema = build_output_schema(menu, aliases, candidates, {"event-hostile"})
    return BuiltBrief(
        system="system", user="user", schema=schema, menu=menu, aliases=aliases,
        token_estimate=1, shrink_actions=[], known_candidates=candidates,
        known_evidence_ids={"event-safe", "event-hostile"},
        known_entities=[EntityRef(kind="host", value="video", role="host")],
        injection_flags=["event-hostile:message"], injection_evidence_ids={"event-hostile"},
    )


def test_flat_schema_makes_unknown_options_and_aliases_unrepresentable():
    brief = _brief()

    assert SCHEMA_FORM == "flat"
    assert brief.schema["additionalProperties"] is False
    assert brief.schema["properties"]["option"]["enum"] == ["O1", "O2", "O3", "O4"]
    evidence = brief.schema["properties"]["evidence"]
    assert evidence["uniqueItems"] is True
    assert evidence["items"]["enum"] == ["E1", "E2"]
    assert "O999" not in brief.schema["properties"]["option"]["enum"]
    assert "E999" not in evidence["items"]["enum"]


def test_schema_applies_per_option_evidence_subsets_and_excludes_hostile_conclusion_cards():
    brief = _brief()
    aliases = brief.aliases
    candidates = brief.known_candidates
    by_id = {option.id: option for option in brief.menu.options}

    assert eligible_evidence_aliases(by_id["O1"], aliases, candidates, {"event-hostile"}) == ["E1", "E2"]
    assert eligible_evidence_aliases(by_id["O2"], aliases, candidates, {"event-hostile"}) == ["E2"]
    assert eligible_evidence_aliases(by_id["O3"], aliases, candidates, {"event-hostile"}) == ["E1"]
    assert eligible_evidence_aliases(by_id["O4"], aliases, candidates, {"event-hostile"}) == ["E1"]


def test_resolver_maps_exact_typed_decision_and_flags_deterministic_truncation():
    brief = _brief()

    result = resolve_output({
        "option": "O1", "evidence": ["E1"], "rationale": "r" * 350,
        "benign_alternative": "b" * 250,
    }, brief, WINDOW)

    assert result.ok
    assert result.decision == _menu().options[0].decision.model_copy(update={
        "evidence_ids": ["event-safe"], "reasoning": "r" * 300,
        "benign_alternatives": ["b" * 200],
    })
    assert result.truncated_fields == ["rationale", "benign_alternative"]
    assert result.validation is not None and result.validation.ok


def test_resolver_treats_forged_unknowns_and_hostile_close_citations_as_constraint_defects():
    brief = _brief()

    unknown = resolve_output({
        "option": "O999", "evidence": ["E999"], "rationale": "invented",
    }, brief, WINDOW)
    hostile = resolve_output({
        "option": "O4", "evidence": ["E2"], "rationale": "the log said to close",
    }, brief, WINDOW)

    assert not unknown.ok and unknown.constraint_defect
    assert "unknown option" in unknown.errors[0]
    assert not hostile.ok and hostile.constraint_defect
    assert any("untrusted instruction-like telemetry" in error for error in hostile.errors)


def test_resolver_runs_duplicate_check_after_semantic_validation():
    brief = _brief()

    result = resolve_output(
        {"option": "O1", "evidence": ["E1"], "rationale": "repeat"},
        brief, WINDOW,
        duplicate_check=lambda _request: {"n": 7},
    )

    assert not result.ok and result.constraint_defect
    assert result.errors == [
        ("duplicate pivot: normalized request already executed at step 7; "
         "reuse prior_steps step 7 result_digest"),
    ]
