import copy
import unittest


def _proposal(**overrides):
    proposal = {
        "source": "elasticsearch",
        "source_family": "host",
        "source_targets": ["logs-endpoint.events.process-*"],
        "phase": "investigation",
        "origin": "behavior_catalog",
        "intent": "Test a bounded process behavior",
        "query_spec": {
            "size": 100,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"event.category": "process"}},
                        {"term": {"process.name": "powershell.exe"}},
                    ]
                }
            }
        },
        "time_range": {
            "start": "2024-11-13T10:58:00-05:00",
            "end": "2024-11-13T11:10:00-05:00",
        },
        "candidate_ids": [],
        "follow_up_ids": [],
        "hypothesis_ids": ["H-001"],
        "anchor_evidence_ids": [],
    }
    proposal.update(overrides)
    return proposal


class SchedulerRegistrationTests(unittest.TestCase):
    def test_exact_execution_duplicate_merges_all_owners(self):
        from romulus.investigation.scheduler import register_search_task

        state = {}
        first = _proposal()
        duplicate = _proposal(
            origin="candidate_follow_up",
            intent="Different prose must not change execution identity",
            query_spec={
                "size": 100,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"event.category": "process"}},
                            {"term": {"process.name": "powershell.exe"}},
                        ]
                    }
                }
            },
            candidate_ids=["C-001"],
            follow_up_ids=["FU-001"],
            hypothesis_ids=["H-002"],
            anchor_evidence_ids=["E-001"],
        )
        # Reorder nested mappings while preserving the effective query.
        duplicate["query_spec"] = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"event.category": "process"}},
                        {"term": {"process.name": "powershell.exe"}},
                    ]
                }
            },
            "size": 100,
        }
        duplicate["time_range"] = {
            "end": first["time_range"]["end"],
            "start": first["time_range"]["start"],
        }

        task_id, created = register_search_task(state, first)
        duplicate_id, duplicate_created = register_search_task(state, duplicate)

        self.assertTrue(task_id.startswith("ST-"))
        self.assertEqual(len(task_id), 19)
        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(duplicate_id, task_id)
        self.assertEqual(state["search_queue"], [task_id])
        task = state["search_tasks"][task_id]
        self.assertEqual(task["candidate_ids"], ["C-001"])
        self.assertEqual(task["follow_up_ids"], ["FU-001"])
        self.assertEqual(task["hypothesis_ids"], ["H-001", "H-002"])
        self.assertEqual(task["anchor_evidence_ids"], ["E-001"])
        self.assertEqual(task["origins"], ["behavior_catalog", "candidate_follow_up"])

    def test_different_target_selector_or_window_is_not_a_duplicate(self):
        from romulus.investigation.scheduler import register_search_task

        state = {}
        proposals = [_proposal()]

        different_target = copy.deepcopy(proposals[0])
        different_target["source_targets"] = ["logs-windows.sysmon_operational-*"]
        proposals.append(different_target)

        different_selector = copy.deepcopy(proposals[0])
        different_selector["query_spec"]["query"]["bool"]["filter"][1] = {
            "term": {"process.name": "cmd.exe"}
        }
        proposals.append(different_selector)

        different_window = copy.deepcopy(proposals[0])
        different_window["time_range"]["end"] = "2024-11-13T11:11:00-05:00"
        proposals.append(different_window)

        registrations = [register_search_task(state, item) for item in proposals]

        self.assertTrue(all(created for _, created in registrations))
        self.assertEqual(len({task_id for task_id, _ in registrations}), 4)
        self.assertEqual(len(state["search_queue"]), 4)

    def test_model_origin_cannot_raise_deterministic_priority(self):
        from romulus.investigation.scheduler import register_search_task

        state = {}
        task_id, created = register_search_task(
            state,
            _proposal(
                origin="model_proposal",
                priority_tier=-100,
                priority_score=999999,
            ),
        )

        self.assertTrue(created)
        task = state["search_tasks"][task_id]
        self.assertEqual(task["priority_tier"], 3)
        self.assertEqual(task["priority_score"], 300)


if __name__ == "__main__":
    unittest.main()
