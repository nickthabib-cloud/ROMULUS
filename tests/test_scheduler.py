import copy
import json
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


class SchedulerOrderingTests(unittest.TestCase):
    def _discovery_state(self):
        from romulus.investigation.scheduler import register_search_task

        state = {"source_health": {"host": True, "network": True}}
        items = [
            _proposal(
                phase="discovery",
                origin="trusted_indicator",
                query_spec={"query": {"term": {"host.name": "alpha"}}},
            ),
            _proposal(
                phase="discovery",
                origin="behavior_catalog",
                query_spec={"query": {"term": {"host.name": "bravo"}}},
            ),
            _proposal(
                phase="discovery",
                origin="behavior_catalog",
                query_spec={"query": {"term": {"host.name": "charlie"}}},
            ),
            _proposal(
                source="arkime",
                source_family="network",
                source_targets=["arkime-primary"],
                phase="discovery",
                origin="coverage_frontier",
                query_spec={"expression": "protocols == tcp"},
            ),
        ]
        for item in items:
            register_search_task(state, item)
        return state

    def test_discovery_reserves_one_task_for_each_healthy_family(self):
        from romulus.investigation.scheduler import select_search_tasks

        selected = select_search_tasks(self._discovery_state(), phase="discovery", limit=3)

        self.assertEqual({item["source_family"] for item in selected[:2]}, {"host", "network"})
        self.assertEqual(selected[0]["origin"], "trusted_indicator")

    def test_investigation_uses_fixed_evidence_value_tiers(self):
        from romulus.investigation.scheduler import register_search_task, select_search_tasks

        state = {}
        items = [
            _proposal(
                origin="candidate_follow_up",
                candidate_priority="medium",
                query_spec={"query": {"term": {"case": "medium"}}},
            ),
            _proposal(
                origin="coverage_frontier",
                query_spec={"query": {"term": {"case": "coverage"}}},
            ),
            _proposal(
                origin="model_proposal",
                anchor_evidence_ids=["E-001"],
                query_spec={"query": {"term": {"case": "model"}}},
            ),
            _proposal(
                origin="directed_survey",
                query_spec={"query": {"term": {"case": "operator"}}},
            ),
            _proposal(
                origin="candidate_follow_up",
                candidate_priority="high",
                query_spec={"query": {"term": {"case": "high"}}},
            ),
            _proposal(
                origin="candidate_follow_up",
                candidate_priority="critical",
                query_spec={"query": {"term": {"case": "critical"}}},
            ),
            _proposal(
                origin="trusted_indicator",
                query_spec={"query": {"term": {"case": "trusted"}}},
            ),
        ]
        for item in items:
            register_search_task(state, item)

        selected = select_search_tasks(state, phase="investigation", limit=len(items))

        self.assertEqual(
            [item["query_spec"]["query"]["term"]["case"] for item in selected],
            ["trusted", "critical", "high", "operator", "model", "coverage", "medium"],
        )

    def test_within_tier_prefers_less_attempted_family_then_score_and_creation(self):
        from romulus.investigation.scheduler import register_search_task, select_search_tasks

        state = {
            "search_outcomes": [
                {"task_id": "ST-OLD", "source_family": "host", "status": "completed"}
            ]
        }
        proposals = [
            _proposal(
                origin="trusted_indicator",
                query_spec={"query": {"term": {"case": "host-trusted"}}},
            ),
            _proposal(
                source="arkime",
                source_family="network",
                source_targets=["arkime-primary"],
                origin="candidate_follow_up",
                candidate_priority="critical",
                query_spec={"expression": "ip.dst == 10.0.0.8"},
            ),
            _proposal(
                source="arkime",
                source_family="network",
                source_targets=["arkime-primary"],
                origin="trusted_indicator",
                query_spec={"expression": "ip.dst == 10.0.0.9"},
            ),
        ]
        for item in proposals:
            register_search_task(state, item)

        selected = select_search_tasks(state, phase="investigation", limit=3)

        self.assertEqual(
            [item["query_spec"] for item in selected],
            [
                {"expression": "ip.dst == 10.0.0.9"},
                {"expression": "ip.dst == 10.0.0.8"},
                {"query": {"term": {"case": "host-trusted"}}},
            ],
        )

    def test_selection_order_survives_json_round_trip(self):
        from romulus.investigation.scheduler import select_search_tasks

        state = self._discovery_state()
        before = [item["task_id"] for item in select_search_tasks(state, phase="discovery", limit=4)]
        restored = json.loads(json.dumps(state))
        after = [item["task_id"] for item in select_search_tasks(restored, phase="discovery", limit=4)]

        self.assertEqual(after, before)

    def test_discovery_budget_gap_is_explicit_when_a_family_cannot_be_served(self):
        from romulus.investigation.scheduler import select_search_tasks

        two_call_state = self._discovery_state()
        selected = select_search_tasks(two_call_state, phase="discovery", limit=2)
        self.assertEqual({item["source_family"] for item in selected}, {"host", "network"})

        one_call_state = self._discovery_state()
        selected = select_search_tasks(one_call_state, phase="discovery", limit=1)
        self.assertEqual(len(selected), 1)
        gaps = [
            event
            for event in one_call_state["scheduler_history"]
            if event.get("event") == "discovery_budget_gap"
        ]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["unserved_families"], ["network"])


class SchedulerOutcomeTests(unittest.TestCase):
    def test_only_complete_uncapped_outcome_with_confirmed_total_resolves(self):
        from romulus.investigation.scheduler import outcome_resolves

        complete_zero = {
            "status": "completed",
            "matched_total": 0,
            "returned_total": 0,
            "capped": False,
            "timed_out": False,
            "shard_failures": 0,
        }
        self.assertTrue(outcome_resolves(complete_zero))
        for change in (
            {"capped": True},
            {"timed_out": True},
            {"shard_failures": 1},
            {"status": "partial"},
            {"status": "failed"},
            {"status": "skipped"},
            {"status": "budget_limited"},
        ):
            with self.subTest(change=change):
                candidate = {**complete_zero, **change}
                self.assertFalse(outcome_resolves(candidate))
        missing_confirmation = dict(complete_zero)
        missing_confirmation.pop("matched_total")
        self.assertFalse(outcome_resolves(missing_confirmation))

    def test_recording_is_task_specific_idempotent_and_terminal(self):
        from romulus.investigation.scheduler import (
            begin_search_task,
            record_search_outcome,
            register_search_task,
            select_search_tasks,
        )

        state = {}
        first_id, _ = register_search_task(state, _proposal())
        second_id, _ = register_search_task(
            state,
            _proposal(query_spec={"query": {"term": {"case": "unrelated"}}}),
        )
        begin_search_task(state, first_id, now="2026-10-12T10:00:00Z")
        supplied = {
            "status": "completed",
            "matched_total": 0,
            "returned_total": 0,
            "capped": False,
            "timed_out": False,
            "artifact_id": "A-001",
        }

        recorded = record_search_outcome(
            state, first_id, supplied, now="2026-10-12T10:01:00Z"
        )
        repeated = record_search_outcome(
            state, first_id, supplied, now="2026-10-12T10:02:00Z"
        )

        self.assertEqual(recorded, repeated)
        self.assertEqual(len(state["search_outcomes"]), 1)
        self.assertEqual(state["search_tasks"][first_id]["status"], "completed")
        self.assertEqual(state["search_tasks"][second_id]["status"], "queued")
        selected_ids = {
            item["task_id"]
            for item in select_search_tasks(state, phase="investigation", limit=10)
        }
        self.assertNotIn(first_id, selected_ids)
        self.assertIn(second_id, selected_ids)

    def test_interrupted_task_retries_once_then_discloses_possible_duplicate(self):
        from romulus.investigation.scheduler import (
            begin_search_task,
            recover_interrupted_tasks,
            register_search_task,
            select_search_tasks,
        )

        state = {}
        task_id, _ = register_search_task(state, _proposal())
        begin_search_task(state, task_id, now="2026-10-12T10:00:00Z")

        first_recovery = recover_interrupted_tasks(state)

        self.assertEqual(first_recovery, [task_id])
        self.assertEqual(state["search_tasks"][task_id]["status"], "interrupted")
        self.assertEqual(state["search_tasks"][task_id]["interruption_count"], 1)
        self.assertEqual(
            [item["task_id"] for item in select_search_tasks(state, phase="investigation")],
            [task_id],
        )

        begin_search_task(state, task_id, now="2026-10-12T10:02:00Z")
        second_recovery = recover_interrupted_tasks(state)

        self.assertEqual(second_recovery, [])
        self.assertEqual(state["search_tasks"][task_id]["status"], "skipped")
        self.assertEqual(
            [item for item in select_search_tasks(state, phase="investigation")], []
        )
        last = state["search_outcomes"][-1]
        self.assertEqual(last["reason"], "repeated_interruption")
        self.assertTrue(last["possible_duplicate_execution"])

    def test_legacy_completed_leads_migrate_conservatively_and_never_rerun(self):
        from romulus.investigation.scheduler import (
            migrate_legacy_search_state,
            outcome_resolves,
            select_search_tasks,
        )

        state = {
            "completed_leads": ["C-H-001", "C-N-002"],
            "lead_catalog": [
                {
                    "id": "C-H-001",
                    "source": "host",
                    "intent": "legacy host search",
                    "terms": ["powershell"],
                    "hypothesis_id": "H-001",
                },
                {
                    "id": "C-N-002",
                    "source": "network",
                    "intent": "legacy network search",
                    "ips": ["10.0.0.8"],
                    "hypothesis_id": "H-002",
                },
            ],
            "pivot_results": [
                {
                    "lead_id": "C-H-001",
                    "status": "searched",
                    "returned": 0,
                    "matched_total": 0,
                    "capped": False,
                }
            ],
            "coverage": {"model_search_results": []},
            "es_indices": ["logs-endpoint-*"],
        }

        migrate_legacy_search_state(state)

        by_legacy_id = {
            task["legacy_lead_id"]: task for task in state["search_tasks"].values()
        }
        completed = by_legacy_id["C-H-001"]
        unknown = by_legacy_id["C-N-002"]
        completed_outcome = next(
            item for item in state["search_outcomes"] if item["task_id"] == completed["task_id"]
        )
        unknown_outcome = next(
            item for item in state["search_outcomes"] if item["task_id"] == unknown["task_id"]
        )
        self.assertTrue(outcome_resolves(completed_outcome))
        self.assertEqual(unknown["status"], "skipped")
        self.assertEqual(unknown_outcome["reason"], "legacy_attempt_unknown")
        self.assertFalse(outcome_resolves(unknown_outcome))
        self.assertEqual(select_search_tasks(state, phase="investigation", limit=10), [])


if __name__ == "__main__":
    unittest.main()
