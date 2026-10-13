import copy
import unittest


def _state():
    return {
        "host": [{"evidence_id": "EV-1", "observation": "stable evidence"}],
        "network": [],
        "candidate_leads": [{
            "candidate_id": "CL-1",
            "disposition": "observed",
            "follow_ups": [{"follow_up_id": "FU-1", "status": "pending"}],
        }],
        "search_tasks": {
            "ST-1": {
                "task_id": "ST-1",
                "execution_fingerprint": "FP-1",
                "status": "completed",
            },
            "ST-2": {
                "task_id": "ST-2",
                "execution_fingerprint": "FP-2",
                "status": "queued",
            },
        },
        "search_outcomes": [{
            "task_id": "ST-1",
            "source": "arkime",
            "status": "completed",
            "matched_total": 0,
            "returned_total": 0,
            "capped": False,
            "timed_out": False,
            "shard_failures": 0,
            "incomplete": False,
        }],
        "hypotheses": [{
            "hypothesis_id": "H-1",
            "status": "supported",
            "model_assessment": {
                "status": "supported",
                "evidence_ids": ["EV-1"],
            },
        }],
        "investigation_graph": {
            "nodes": [{"node_id": "N-1"}],
            "edges": [{"edge_id": "E-1"}],
            "paths": [{"path_id": "P-1"}],
        },
        "coverage": {
            "hypothesis_coverage": {
                "rows": [{
                    "hypothesis_id": "H-2",
                    "closed": False,
                    "unresolved_task_ids": ["ST-2"],
                }],
                "untested_hypotheses": ["H-2"],
                "candidate_rows": [{
                    "candidate_id": "CL-2",
                    "closed": False,
                    "unfinished_follow_up_ids": ["FU-2"],
                    "unresolved_task_ids": ["ST-2"],
                }],
                "open_candidate_ids": ["CL-2"],
                "closure_ready": False,
            }
        },
        "summary": "original summary",
        "reasoning_history": [{"reasoning": "original prose"}],
    }


class ProgressSnapshotTests(unittest.TestCase):
    def test_snapshot_marks_stable_investigation_transitions(self):
        from romulus.investigation.progress import snapshot_progress

        snapshot = snapshot_progress(_state())

        self.assertEqual(snapshot, {
            "evidence_ids": ["EV-1"],
            "candidate_states": {
                "CL-1": {
                    "disposition": "observed",
                    "follow_ups": ["FU-1:pending"],
                }
            },
            "search_fingerprints": ["FP-1", "FP-2"],
            "resolving_task_ids": ["ST-1"],
            "hypothesis_states": {
                "H-1": {
                    "status": "supported",
                    "assessment": "supported",
                    "evidence_ids": ["EV-1"],
                }
            },
            "graph_node_ids": ["N-1"],
            "graph_edge_ids": ["E-1"],
            "path_ids": ["P-1"],
            "open_gap_ids": [
                "candidate:CL-2",
                "follow_up:FU-2",
                "hypothesis:H-2",
                "task:ST-2",
            ],
        })

    def test_compare_progress_ignores_prose_duplicates_and_raw_count_churn(self):
        from romulus.investigation.progress import compare_progress, snapshot_progress

        before = snapshot_progress(_state())
        changed = copy.deepcopy(_state())
        changed["summary"] = "different prose"
        changed["reasoning_history"] = [{"reasoning": "new model prose"}]
        changed["host"].append(copy.deepcopy(changed["host"][0]))
        changed["candidate_leads"].append(copy.deepcopy(changed["candidate_leads"][0]))
        changed["coverage"]["raw_count"] = 999999
        changed["investigation_graph"]["nodes"].reverse()

        assessment = compare_progress(before, snapshot_progress(changed))

        self.assertFalse(assessment["material_progress"])
        self.assertEqual(assessment["signals"], {})
        self.assertEqual(assessment["changed_ids"], {})

    def test_compare_progress_distinguishes_resolving_zero_from_repeated_terminal_state(self):
        from romulus.investigation.progress import compare_progress, snapshot_progress

        unresolved = _state()
        unresolved["search_outcomes"] = []
        before = snapshot_progress(unresolved)
        resolved = snapshot_progress(_state())

        first = compare_progress(before, resolved)
        repeated = compare_progress(resolved, snapshot_progress(copy.deepcopy(_state())))

        self.assertTrue(first["material_progress"])
        self.assertEqual(first["signals"], {"new_resolving_outcomes": 1})
        self.assertEqual(first["changed_ids"], {"new_resolving_outcomes": ["ST-1"]})
        self.assertFalse(repeated["material_progress"])
        self.assertEqual(repeated["signals"], {})
        self.assertEqual(repeated["changed_ids"], {})


class ProgressLedgerTests(unittest.TestCase):
    def test_initialize_progress_baselines_legacy_state_without_incrementing_stagnation(self):
        from romulus.investigation.progress import initialize_progress, snapshot_progress

        state = _state()
        initialize_progress(state)

        self.assertEqual(state["progress_baseline"], snapshot_progress(state))
        self.assertEqual(state["progress_history"], [])
        self.assertEqual(state["stagnant_cycles"], 0)

    def test_record_progress_resets_after_material_change_and_bounds_history(self):
        from romulus.investigation.progress import (
            initialize_progress,
            record_progress,
            summarize_progress,
        )

        state = _state()
        initialize_progress(state)
        for index in range(105):
            assessment = record_progress(state, f"unchanged-{index}")
        self.assertFalse(assessment["material_progress"])
        self.assertEqual(state["stagnant_cycles"], 105)
        self.assertEqual(len(state["progress_history"]), 100)

        state["host"].append({"evidence_id": "EV-2"})
        productive = record_progress(state, "new-evidence")
        summary = summarize_progress(state)

        self.assertTrue(productive["material_progress"])
        self.assertEqual(productive["signals"], {"new_evidence": 1})
        self.assertEqual(state["stagnant_cycles"], 0)
        self.assertEqual(summary["cycles_recorded"], 100)
        self.assertEqual(summary["productive_cycles"], 1)
        self.assertEqual(summary["current_stagnant_cycles"], 0)
        self.assertEqual(summary["signal_totals"], {"new_evidence": 1})
        self.assertEqual(summary["last_stage"], "new-evidence")

    def test_nonresolving_low_value_search_without_state_change_advances_stagnation(self):
        from romulus.investigation.progress import initialize_progress, record_progress

        state = _state()
        initialize_progress(state)
        state["search_tasks"]["ST-3"] = {
            "task_id": "ST-3",
            "execution_fingerprint": "FP-3",
            "priority_tier": 4,
            "status": "queued",
        }
        registered = record_progress(state, "reason")
        self.assertTrue(registered["material_progress"])
        self.assertEqual(state["stagnant_cycles"], 0)

        state["search_tasks"]["ST-3"]["status"] = "partial"
        state["search_outcomes"].append({
            "task_id": "ST-3",
            "source": "arkime",
            "status": "partial",
            "matched_total": 100,
            "returned_total": 10,
            "capped": True,
            "timed_out": False,
            "shard_failures": 0,
            "incomplete": True,
        })
        completed = record_progress(state, "analysis")

        self.assertFalse(completed["material_progress"])
        self.assertEqual(state["stagnant_cycles"], 1)


class StopDecisionTests(unittest.TestCase):
    def _decide(self, **updates):
        from romulus.investigation.progress import decide_next_action

        values = {
            "hard_limit_reason": None,
            "reasoning_limit_reason": None,
            "coverage_closed": False,
            "queued_priority_tier": None,
            "grounded": True,
            "can_reason": True,
            "just_reasoned": False,
            "stagnant_cycles": 0,
            "max_stagnant_cycles": 3,
        }
        values.update(updates)
        return decide_next_action(**values)

    def test_stop_decision_preserves_limit_closure_and_high_value_precedence(self):
        self.assertEqual(
            self._decide(hard_limit_reason="runtime_budget", coverage_closed=True,
                         queued_priority_tier=1),
            {"action": "report", "termination_reason": "runtime_budget"},
        )
        self.assertEqual(
            self._decide(coverage_closed=True, queued_priority_tier=1),
            {"action": "report", "termination_reason": "coverage_closure_reached"},
        )
        self.assertEqual(
            self._decide(queued_priority_tier=2, stagnant_cycles=3),
            {"action": "pivot"},
        )

    def test_stop_decision_stops_stagnant_breadth_and_never_reads_model_advice(self):
        self.assertEqual(
            self._decide(queued_priority_tier=4, stagnant_cycles=3),
            {"action": "report", "termination_reason": "no_productive_frontier"},
        )
        self.assertEqual(
            self._decide(queued_priority_tier=4),
            {"action": "reason"},
        )
        self.assertEqual(
            self._decide(queued_priority_tier=4, just_reasoned=True),
            {"action": "pivot"},
        )
        self.assertEqual(
            self._decide(can_reason=False, reasoning_limit_reason="depth_budget"),
            {"action": "report", "termination_reason": "depth_budget"},
        )
        self.assertEqual(
            self._decide(grounded=False),
            {"action": "report", "termination_reason": "no_productive_frontier"},
        )


if __name__ == "__main__":
    unittest.main()
