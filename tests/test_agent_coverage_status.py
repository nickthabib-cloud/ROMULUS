"""The agent's coverage view is partial whenever any rule searched only part of its scope, even with no gap rows."""
from __future__ import annotations

import pytest

import romulus.agent.toolbox as toolbox_module
from romulus.agent.toolbox import Toolbox


def _coverage_status(monkeypatch, search_result: str) -> str:
    canonical = {"rules": [{"rule_id": "r1", "states": {}, "records_evaluated": 0, "search_result": search_result}],
                 "gaps": [], "not_assessed": []}
    monkeypatch.setattr(toolbox_module, "coverage_for_rules", lambda _repo, _hunt, _rules: canonical)
    box = object.__new__(Toolbox)
    box.repo, box.hunt_id = None, "h1"
    return box._coverage({"r1"})["status"]


@pytest.mark.parametrize("search_result", [
    "searched in part: sweep did not finish",
    "none (rule matched); coverage incomplete: sweep did not finish",
])
def test_a_rule_searched_in_part_makes_coverage_partial_without_gaps(monkeypatch, search_result):
    assert _coverage_status(monkeypatch, search_result) == "partial"


def test_a_full_search_with_no_gaps_is_complete_coverage(monkeypatch):
    assert _coverage_status(monkeypatch, "searched in full: 4 record(s) evaluated, none matched") == "complete"
