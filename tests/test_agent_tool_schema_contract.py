"""The schema each agent tool advertises is the schema its validator enforces, and the assessment's response schema is
the one its reply is checked against.

For every tool, representative arguments are checked both ways: what the argument model accepts, the advertised JSON
schema accepts, and what the model refuses, the schema refuses. The few rules a JSON schema cannot state are listed
by name, and each is stated in the tool's descriptions instead. A strict tool's server-side form (bounds and
patterns moved into words) accepts every accepted argument set once its defaults are written out. The checker here is
a small JSON-schema evaluator for the keywords the argument models emit, so a bound the schema drops is caught.
"""
import re
from copy import deepcopy

import pytest
from pydantic import ValidationError

from romulus.agent.admission import AgentAdmission
from romulus.agent.aliases import AliasBook
from romulus.agent.assessment import (
    ASSESSMENT_SCHEMA,
    CITE_LIMIT,
    SECTION_LIMITS,
    TEXT_LIMIT,
    AssessmentBody,
    check_assessment,
)
from romulus.agent.provider.claude_messages import _format_ok, instance_problems, strict_wire_schema
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.detect.registry import ALL_PLAYBOOKS
from tests.test_report import _repo_with_finding

RULE = ALL_PLAYBOOKS[0].id
WHEN = "2024-11-18T10:00:00Z"
LATER = "2024-11-18T11:00:00+00:00"


def _same(a, b) -> bool:
    return a == b and isinstance(a, bool) == isinstance(b, bool)


def _typed(value, kind: str) -> bool:
    if kind in ("integer", "number") and isinstance(value, bool):
        return False
    python = {"integer": int, "number": (int, float), "string": str, "boolean": bool, "object": dict,
              "array": list, "null": type(None)}[kind]
    return isinstance(value, python)


def accepts(value, schema: dict, root: dict | None = None) -> bool:
    """Whether `value` is valid under `schema`, for the keywords argument models emit."""
    root = root if root is not None else schema
    if "$ref" in schema:
        return accepts(value, root["$defs"][schema["$ref"].rsplit("/", 1)[1]], root)
    if "anyOf" in schema and not any(accepts(value, sub, root) for sub in schema["anyOf"]):
        return False
    if not all(accepts(value, sub, root) for sub in schema.get("allOf", [])):
        return False
    if "const" in schema and not _same(value, schema["const"]):
        return False
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        return False
    kinds = schema.get("type")
    if kinds is not None and not any(_typed(value, k) for k in (kinds if isinstance(kinds, list) else [kinds])):
        return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            return False
        if "pattern" in schema and not re.search(schema["pattern"], value):
            return False
        if "format" in schema and not _format_ok(value, schema["format"]):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            return False
        if "items" in schema and not all(accepts(item, schema["items"], root) for item in value):
            return False
    if isinstance(value, dict) and (schema.get("type") == "object" or "properties" in schema):
        properties = schema.get("properties", {})
        if any(name not in value for name in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        if not all(accepts(value[name], sub, root) for name, sub in properties.items() if name in value):
            return False
    return True


def window(**extra):
    return {"anchor": "F1", **extra}


# (arguments, accepted by the argument model)
CASES: dict[str, list[tuple[dict, bool]]] = {
    "list_findings": [
        ({}, True), ({"lane": "high"}, True), ({"lane": None, "page": 1}, True), ({"rule": RULE}, True),
        ({"entity": "N3", "page": 2, "cursor": "D" + "a" * 16}, True), ({"rule": None, "entity": None}, True),
        ({"lane": "bogus"}, False), ({"page": 0}, False), ({"page": 1.5}, False), ({"cursor": "Dxyz"}, False),
        ({"entity": "X1"}, False), ({"entity": "N0"}, False), ({"extra": 1}, False),
    ],
    "get_finding": [({"finding": "F1"}, True), ({"finding": "F12"}, True),
                    ({}, False), ({"finding": "F0"}, False), ({"finding": "f1"}, False), ({"finding": 1}, False)],
    "list_coverage": [({}, True), ({"page": 2, "cursor": "C" + "0" * 20}, True), ({"cursor": None}, True),
                      ({"cursor": "C1"}, False), ({"page": 0}, False)],
    "get_evidence": [
        ({"evidence": ["E1"]}, True), ({"evidence": ["E1"] * 20, "chunk_index": 2, "raw_page": 3}, True),
        ({"evidence": []}, False), ({"evidence": ["E1"] * 21}, False), ({}, False),
        ({"evidence": ["E1"], "raw_page": 0}, False), ({"evidence": ["E1"], "chunk_index": 0}, False),
        ({"evidence": ["H1"]}, False),
    ],
    "list_incidents": [({}, True), ({"page": 3, "cursor": "J" + "f" * 20}, True), ({"cursor": "G" + "f" * 20}, False)],
    "get_incident": [({"incident": "I1"}, True), ({"incident": "I1", "page": 2, "cursor": "G" + "1" * 20}, True),
                     ({}, False), ({"incident": "I1", "cursor": "G1"}, False)],
    "entity_profile": [({"entity": "N1"}, True), ({"entity": "N1", "chunk_index": 4}, True),
                       ({"entity": "N1", "cursor": "R" + "0" * 19}, False), ({"entity": "N1", "page": -1}, False)],
    "entity_timeline": [
        (window(entity="N2"), True), (window(entity="N2", start=WHEN, end=LATER), True),
        (window(entity="N2", start=None, end=None), True), (window(entity="N2", cursor="P" + "a" * 20), True),
        (window(), False), ({"entity": "N2"}, False), (window(entity="N2", start="2024-11-18T10:00:00"), False),
        (window(entity="N2", start="yesterday"), False), (window(entity="N2", cursor="P" + "a" * 21), False),
    ],
    "auth_activity": [(window(entity="N2", end=LATER), True), (window(entity="N2", page=0), False)],
    "process_tree": [(window(process="E4"), True), (window(entity="N2"), False)],
    "ids_alerts": [(window(entity="N9", start=WHEN), True), (window(entity="N9", extra=True), False)],
    "follow_link": [
        ({"anchor": "F1", "link_type": "account"}, True),
        ({"anchor": "F1", "link_type": "process_lineage", "window": "anchor ±2 h", "page": 1}, True),
        ({"anchor": "F1", "link_type": "account", "window": None}, True),
        ({"anchor": "F1", "link_type": "dns"}, False), ({"anchor": "F1", "link_type": "account", "window": "1h"}, False),
        ({"link_type": "account"}, False),
    ],
    "open_hypothesis": [
        ({"statement": "s" * 10}, True),
        ({"statement": "s" * 600, "techniques": ["T1059.001"] * 20, "entities": ["N1"] * 40,
          "supporting": ["F1", "E2", "L3", "A4"], "questions": ["q" * 300] * 8}, True),
        ({"statement": "s" * 9}, False), ({"statement": "s" * 601}, False),
        ({"statement": "s" * 10, "techniques": ["T"]}, False), ({"statement": "s" * 10, "techniques": ["T" * 17]}, False),
        ({"statement": "s" * 10, "techniques": ["T1059"] * 21}, False),
        ({"statement": "s" * 10, "entities": ["N1"] * 41}, False),
        ({"statement": "s" * 10, "questions": ["q"] * 9}, False), ({"statement": "s" * 10, "questions": [""]}, False),
        ({"statement": "s" * 10, "questions": ["q" * 301]}, False), ({"statement": "s" * 10, "supporting": ["Z1"]}, False),
        ({"statement": "s" * 10, "status": "open"}, False),
    ],
    "update_hypothesis": [
        ({"hypothesis": "H1", "note": "n"}, True),
        ({"hypothesis": "H1", "note": "n", "status": None, "confidence": None, "questions": None}, True),
        ({"hypothesis": "H1", "note": "n" * 600, "status": "supported", "confidence": "high",
          "add_support": ["F1"] * 20, "add_contradiction": ["E2"], "questions": []}, True),
        ({"hypothesis": "H1", "note": ""}, False), ({"hypothesis": "H1", "note": "n" * 601}, False),
        ({"hypothesis": "H1", "note": "n", "status": "closed"}, False),
        ({"hypothesis": "H1", "note": "n", "confidence": "certain"}, False),
        ({"hypothesis": "H1", "note": "n", "add_support": ["F1"] * 21}, False),
        ({"hypothesis": "H1", "note": "n", "questions": ["q"] * 9}, False), ({"note": "n"}, False),
    ],
    "propose_finding": [
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": ["E1"], "lane": "high"}, True),
        ({"claim": "c" * 400, "claim_kind": "mention", "cites": ["E1"] * 20, "lane": "context",
          "techniques": ["T1003"], "rationale": "r" * 1000, "hypothesis": "H2"}, True),
        ({"claim": "c" * 10, "claim_kind": "network", "cites": ["E1"], "lane": "lead", "hypothesis": None}, True),
        ({"claim": "c" * 9, "claim_kind": "execution", "cites": ["E1"], "lane": "high"}, False),
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": [], "lane": "high"}, False),
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": ["E1"] * 21, "lane": "high"}, False),
        ({"claim": "c" * 10, "claim_kind": "malware", "cites": ["E1"], "lane": "high"}, False),
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": ["E1"], "lane": "critical"}, False),
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": ["E1"], "lane": "high", "rationale": "r" * 1001},
         False),
        ({"claim": "c" * 10, "claim_kind": "execution", "cites": ["E1"]}, False),
    ],
    "propose_link": [
        ({"from": "F1", "to": "N2", "relation": "related", "cites": ["E1"], "rationale": "r"}, True),
        ({"from": "F1", "to": "F2", "relation": "lateral_movement", "cites": ["L1"] * 20, "rationale": "r" * 1000},
         True),
        ({"from_": "F1", "to": "N2", "relation": "related", "cites": ["E1"], "rationale": "r"}, False),
        ({"from": "F1", "to": "N2", "relation": "related", "cites": ["E1"], "rationale": ""}, False),
        ({"from": "F1", "to": "N2", "relation": "causes", "cites": ["E1"], "rationale": "r"}, False),
    ],
    "add_note": [({"target": "F1", "text": "t"}, True), ({"target": "H1", "text": "t" * 1000, "cites": ["E1"]}, True),
                 ({"target": "F1", "text": "t" * 1001}, False), ({"target": "F1"}, False),
                 ({"target": "F1", "text": "t", "cites": ["E1"] * 21}, False)],
    "request_rule": [({"pattern_description": "p" * 20, "cites": ["E1"]}, True),
                     ({"pattern_description": "p" * 19, "cites": ["E1"]}, False),
                     ({"pattern_description": "p" * 1001, "cites": ["E1"]}, False),
                     ({"pattern_description": "p" * 20, "cites": []}, False)],
    "finish_session": [({"summary": "s" * 20}, True), ({"summary": "s" * 2000}, True),
                       ({"summary": "s" * 19}, False), ({"summary": "s" * 2001}, False), ({}, False),
                       ({"summary": "s" * 20, "status": "done"}, False)],
}

# Rules the schema cannot state, each named in the tool's descriptions: the schema accepts these, the model refuses.
SCHEMA_CANNOT_STATE = {
    "list_findings": [({"rule": "not.a.registered.rule"}, "registered rule")],
    "entity_timeline": [(window(entity="N2", start=LATER, end=WHEN), "start must be before end")],
    "finish_session": [({"summary": " " * 25}, "surrounding whitespace is not counted")],
}


@pytest.fixture(scope="module")
def registry(tmp_path_factory):
    from romulus.hunt.run import open_repo
    home = tmp_path_factory.mktemp("contract")
    repo = open_repo(Settings(home=home))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "d", "test")
    toolbox = Toolbox(repo, "h1")
    AgentAdmission(Settings(home=home), repo, "h1", "as-test").register(toolbox)
    return toolbox.registry


def _validator_accepts(tool, arguments) -> bool:
    try:
        tool.arguments.model_validate(arguments)
    except ValidationError:
        return False
    return True


def test_every_tool_has_contract_cases(registry):
    assert set(CASES) == set(registry)
    for name, cases in CASES.items():
        assert any(ok for _, ok in cases) and any(not ok for _, ok in cases), name


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_advertised_schema_accepts_exactly_what_the_validator_accepts(registry, name):
    tool = registry[name]
    schema = tool.provider_tool().parameters
    for arguments, ok in CASES[name]:
        assert _validator_accepts(tool, arguments) is ok, (name, arguments)
        assert accepts(arguments, schema) is ok, (name, arguments)
    for arguments, rule in SCHEMA_CANNOT_STATE.get(name, []):
        assert accepts(arguments, schema) and not _validator_accepts(tool, arguments), (name, rule)


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_strict_tool_sent_form_accepts_every_accepted_argument_set_written_out(registry, name):
    tool = registry[name]
    if not tool.strict:
        return
    wire = strict_wire_schema(tool.provider_tool().parameters)
    for arguments, ok in CASES[name]:
        if ok:
            explicit = tool.arguments.model_validate(arguments).model_dump(mode="json", by_alias=True,
                                                                           exclude_none=True)
            assert instance_problems(explicit, wire) == [], (name, arguments)
            assert accepts(explicit, wire), (name, arguments)


def test_the_bounds_a_strict_form_cannot_carry_are_stated_to_the_model(registry):
    for name, tool in registry.items():
        if not tool.strict:
            continue
        exact = tool.provider_tool().parameters
        wire = strict_wire_schema(exact)
        for prop, sub in exact["properties"].items():
            for key, value in sub.items():
                if key in ("minLength", "maxLength", "maxItems"):
                    assert str(value) in wire["properties"][prop]["description"], (name, prop, key)


# ---- the assessment ----------------------------------------------------------------------------------------------

@pytest.fixture
def repo():
    value, _ = _repo_with_finding()
    yield value
    value.engine.dispose()


def _sentence(alias, text="The recorded process ran on the host.", kind="observed", cites=None):
    return {"text": text, "cites": cites if cites is not None else [alias], "kind": kind}


def _reply(alias, **sections):
    body = {"overall": [_sentence(alias)], "key_steps": [], "confidence": {"overall": "medium", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    body.update(sections)
    return body


def _schema_valid(body) -> bool:
    return accepts(body, ASSESSMENT_SCHEMA) and not instance_problems(body, strict_wire_schema(ASSESSMENT_SCHEMA))


def test_a_reply_the_response_schema_allows_passes_validation_and_the_bounds_are_applied_and_counted(repo):
    alias = AliasBook(repo, "h1").alias_for("E", "ev1")
    step = {"time": WHEN, "tactic": "Execution", "sentence": _sentence(alias)}
    over = _reply(
        alias,
        overall=[_sentence(alias)] * (SECTION_LIMITS["overall"] + 2),
        key_steps=[step, {"time": None, "tactic": None, "sentence": _sentence(alias, kind="inferred")}],
        gaps=[_sentence(alias, text="x" * (TEXT_LIMIT + 1)), _sentence(alias, text="   ")],
        next_checks=[_sentence(alias, cites=[alias] * (CITE_LIMIT + 5))],
    )
    assert _schema_valid(over)
    AssessmentBody.model_validate(over)                  # the shape the schema allows is the shape validated
    checked, counts = check_assessment(repo, "h1", deepcopy(over))
    assert len(checked["overall"]) == SECTION_LIMITS["overall"] and len(checked["key_steps"]) == 2
    assert checked["gaps"] == [] and checked["next_checks"][0]["cites"] == ["ev1"] * CITE_LIMIT
    assert counts == {"dropped_over_cap": 2, "removed_over_length": 1, "removed_empty": 1, "trimmed_citations": 5}


def test_a_reply_the_response_schema_refuses_is_refused_by_validation(repo):
    alias = AliasBook(repo, "h1").alias_for("E", "ev1")
    for broken in (_reply(alias, overall=[_sentence(alias, kind="fact")]),
                   _reply(alias, overall=[_sentence(alias, cites=["ev1"])]),
                   _reply(alias, confidence={"overall": "certain", "reasons": []}),
                   {k: v for k, v in _reply(alias).items() if k != "gaps"},
                   _reply(alias, extra=[]),
                   _reply(alias, key_steps=[{"time": "noon", "tactic": None, "sentence": _sentence(alias)}])):
        assert not accepts(broken, ASSESSMENT_SCHEMA), broken
        with pytest.raises(ValidationError):
            AssessmentBody.model_validate(broken)


def test_the_retry_after_a_bad_reply_names_what_was_wrong():
    from romulus.agent.assessment import _validation_summary
    try:
        AssessmentBody.model_validate({"overall": [{"text": "t", "cites": ["E1"], "kind": "fact"}]})
    except ValidationError as exc:
        summary = _validation_summary(exc, None)
    assert "overall.0.kind" in summary and "key_steps: Field required" in summary
    assert len(summary) < 1000 and "fact" not in summary          # paths and messages, never the values
