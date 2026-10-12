import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


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
    def test_state_sampling_policy_is_persisted_in_task_identity(self):
        from romulus.investigation.scheduler import register_search_task

        first_state = {"sampling_policy": {"version": 1, "strategy": "time_or_rank_stratified", "strata": 4}}
        second_state = {"sampling_policy": {"version": 1, "strategy": "time_or_rank_stratified", "strata": 8}}
        proposal = _proposal(query_spec={"query": {"match_all": {}},
            "sampling": {"version": 99, "strategy": "caller_override", "strata": 24}})

        first_id, _ = register_search_task(first_state, proposal)
        second_id, _ = register_search_task(second_state, proposal)

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(first_state["search_tasks"][first_id]["query_spec"]["sampling"], first_state["sampling_policy"])
        self.assertEqual(second_state["search_tasks"][second_id]["query_spec"]["sampling"], second_state["sampling_policy"])

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

    def test_nonexecuting_family_and_scope_labels_do_not_defeat_deduplication(self):
        from romulus.investigation.scheduler import register_search_task

        state = {}
        first = _proposal(time_range={
            "start": "2024-11-13T10:58:00-05:00",
            "end": "2024-11-13T11:10:00-05:00",
            "scope": "operator mission window",
        })
        duplicate = _proposal(
            source_family="network",
            origin="coverage_frontier",
            time_range={
                "scope": "same fixed UTC-compatible bounds described differently",
                "end": "2024-11-13T11:10:00-05:00",
                "start": "2024-11-13T10:58:00-05:00",
            },
        )

        first_id, first_created = register_search_task(state, first)
        duplicate_id, duplicate_created = register_search_task(state, duplicate)

        self.assertTrue(first_created)
        self.assertFalse(duplicate_created)
        self.assertEqual(duplicate_id, first_id)
        self.assertEqual(len(state["search_tasks"]), 1)

    def test_equivalent_timezone_bounds_share_one_execution_fingerprint(self):
        from romulus.investigation.scheduler import register_search_task

        state = {}
        first = _proposal(time_range={
            "start": "2024-11-13T10:58:00-05:00",
            "end": "2024-11-13T11:10:00-05:00",
        })
        duplicate = _proposal(time_range={
            "start": "2024-11-13T15:58:00Z",
            "end": "2024-11-13T16:10:00Z",
        })

        first_id, first_created = register_search_task(state, first)
        duplicate_id, duplicate_created = register_search_task(state, duplicate)

        self.assertTrue(first_created)
        self.assertFalse(duplicate_created)
        self.assertEqual(duplicate_id, first_id)

    def test_invalid_or_half_bounded_time_ranges_are_rejected(self):
        from romulus.investigation.scheduler import register_search_task

        for time_range in (
            {"start": "2024-11-13T10:58:00Z"},
            {"end": "2024-11-13T11:10:00Z"},
            {"start": "not-a-time", "end": "2024-11-13T11:10:00Z"},
            {"start": "2024-11-13T11:10:00Z", "end": "2024-11-13T10:58:00Z"},
        ):
            with self.subTest(time_range=time_range):
                with self.assertRaises(ValueError):
                    register_search_task({}, _proposal(time_range=time_range))

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
    def test_outcome_preserves_only_bounded_sampling_summary(self):
        from romulus.investigation.scheduler import begin_search_task, record_search_outcome, register_search_task

        state = {}
        task_id, _ = register_search_task(state, _proposal())
        begin_search_task(state, task_id, now="2026-10-12T10:00:00Z")

        recorded = record_search_outcome(state, task_id, {
            "status": "partial", "matched_total": 100, "returned_total": 8,
            "capped": True, "incomplete": True,
            "sampling": {
                "version": 1, "strategy": "rank_stratified", "requested_strata": 8,
                "covered_strata": 7, "retained_by_stratum": [1] * 40,
                "fallback_reason": "offset limit", "windows": [{"request": "must not persist"}],
                "query": {"secret": "must not persist"},
            },
        }, now="2026-10-12T10:01:00Z")

        self.assertEqual(recorded["sampling"]["strategy"], "rank_stratified")
        self.assertEqual(recorded["sampling"]["covered_strata"], 7)
        self.assertEqual(len(recorded["sampling"]["retained_by_stratum"]), 24)
        self.assertNotIn("windows", recorded["sampling"])
        self.assertNotIn("query", recorded["sampling"])
        self.assertFalse(__import__("romulus.investigation.scheduler", fromlist=["outcome_resolves"]).outcome_resolves(recorded))

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
            "completed_leads": ["C-H-001", "C-N-002", "C-U-003", "C-T-005"],
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
                {
                    "id": "C-U-003",
                    "source": "host",
                    "intent": "legacy search with unknown completeness",
                    "terms": ["cmd"],
                    "hypothesis_id": "H-003",
                },
                {
                    "id": "C-P-004",
                    "source": "host",
                    "intent": "pending legacy search",
                    "terms": ["rundll32"],
                    "hypothesis_id": "H-004",
                },
                {
                    "id": "C-T-005",
                    "source": "host",
                    "intent": "legacy timed-out search",
                    "terms": ["wmic"],
                    "hypothesis_id": "H-005",
                },
            ],
            "pivot_results": [
                {
                    "lead_id": "C-H-001",
                    "status": "searched",
                    "returned": 0,
                    "matched_total": 0,
                    "capped": False,
                    "timed_out": False,
                    "shard_failures": 0,
                },
                {
                    "lead_id": "C-U-003",
                    "status": "searched",
                    "returned": 0,
                    "capped": False,
                },
                {
                    "lead_id": "C-T-005",
                    "status": "searched",
                    "returned": 0,
                    "matched_total": 0,
                    "capped": False,
                    "timed_out": True,
                    "shard_failures": 0,
                },
            ],
            "coverage": {"model_search_results": []},
            "es_indices": ["logs-endpoint-*"],
        }

        def compile_pending(lead):
            return [_proposal(
                origin="coverage_frontier",
                intent=lead["intent"],
                hypothesis_ids=[lead["hypothesis_id"]],
                query_spec={"query":{"term":{"process.name":lead["terms"][0]}}},
            )]

        migrate_legacy_search_state(state, compile_pending=compile_pending)

        by_legacy_id = {
            task["legacy_lead_id"]: task for task in state["search_tasks"].values()
        }
        completed = by_legacy_id["C-H-001"]
        unknown = by_legacy_id["C-N-002"]
        unknown_completeness = by_legacy_id["C-U-003"]
        timed_out = by_legacy_id["C-T-005"]
        pending = by_legacy_id["C-P-004"]
        completed_outcome = next(
            item for item in state["search_outcomes"] if item["task_id"] == completed["task_id"]
        )
        unknown_outcome = next(
            item for item in state["search_outcomes"] if item["task_id"] == unknown["task_id"]
        )
        unknown_completeness_outcome = next(item for item in state["search_outcomes"]
            if item["task_id"] == unknown_completeness["task_id"])
        timed_out_outcome = next(item for item in state["search_outcomes"]
            if item["task_id"] == timed_out["task_id"])
        self.assertTrue(outcome_resolves(completed_outcome))
        self.assertEqual(unknown["status"], "skipped")
        self.assertEqual(unknown_outcome["reason"], "legacy_attempt_unknown")
        self.assertFalse(outcome_resolves(unknown_outcome))
        self.assertEqual(unknown_completeness_outcome["reason"], "legacy_completeness_unknown")
        self.assertFalse(outcome_resolves(unknown_completeness_outcome))
        self.assertEqual(timed_out_outcome["status"],"partial")
        self.assertTrue(timed_out_outcome["incomplete"])
        self.assertFalse(outcome_resolves(timed_out_outcome))
        self.assertEqual(pending["status"], "queued")
        self.assertEqual([item["task_id"] for item in
            select_search_tasks(state, phase="investigation", limit=10)], [pending["task_id"]])


class SchedulerResumeIntegrationTests(unittest.TestCase):
    def test_real_sqlite_graph_resume_retries_running_task_once(self):
        try:
            import langgraph  # noqa: F401
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("Install requirements.txt for the real LangGraph/SQLite resume check")

        from romulus.config import Settings
        from romulus.investigation.scheduler import (begin_search_task, record_search_outcome,
            register_search_task)
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root=Path(directory)
            settings=replace(Settings.from_env(),home=root,data_dir=root/"data",logs_dir=root/"logs",
                reports_dir=root/"reports",retention_policy="full",max_depth=1,
                min_reasoning_rounds=0,max_tool_calls=20)
            store=Store(settings.data_dir,settings.logs_dir)
            engine=HuntEngine(settings,store,offline=True,use_ollama=False)
            normal_graph=engine._graph
            with patch.object(engine,"_graph",side_effect=lambda:normal_graph(interrupt_before=["pivot"])):
                interrupted=engine.run("Hunt SMB lateral movement",hunt_id="HUNT-REAL-RESUME")

            config={"configurable":{"thread_id":interrupted["hunt_id"]},"recursion_limit":100}
            app,connection=normal_graph()
            try:
                snapshot=app.get_state(config)
                self.assertIn("pivot",snapshot.next)
                checkpoint=copy.deepcopy(snapshot.values)
                running_id=checkpoint["search_queue"][0]
                begin_search_task(checkpoint,running_id,now="2026-10-12T10:00:00Z")
                terminal_id,_=register_search_task(checkpoint,_proposal(
                    source_targets=["offline-synthetic"],
                    query_spec={"query":{"term":{"case":"already-terminal"}},"size":1},
                    time_range={"scope":"synthetic fixture timestamps"},
                ))
                begin_search_task(checkpoint,terminal_id,now="2026-10-12T10:00:01Z")
                record_search_outcome(checkpoint,terminal_id,{"status":"completed","matched_total":0,
                    "returned_total":0,"capped":False,"timed_out":False,"shard_failures":0},
                    now="2026-10-12T10:00:02Z")
                app.update_state(config,checkpoint)
                store.save_state(checkpoint["hunt_id"],checkpoint)
            finally:
                connection.close()

            resumed=engine.resume(checkpoint["hunt_id"])

            self.assertEqual(resumed["search_tasks"][running_id]["attempt_count"],2)
            self.assertEqual(resumed["search_tasks"][running_id]["interruption_count"],1)
            self.assertEqual(resumed["search_tasks"][running_id]["status"],"completed")
            self.assertEqual(resumed["search_tasks"][terminal_id]["attempt_count"],1)
            terminal_outcomes=[item for item in resumed["search_outcomes"]
                if item["task_id"]==terminal_id and item["status"]=="completed"]
            self.assertEqual(len(terminal_outcomes),1)

    def test_resume_migrates_and_recovers_before_checkpoint_execution(self):
        from romulus.config import Settings
        from romulus.investigation.scheduler import begin_search_task, register_search_task
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root=Path(directory)
            settings=replace(Settings.from_env(),home=root,data_dir=root/"data",logs_dir=root/"logs",
                reports_dir=root/"reports",retention_policy="full")
            store=Store(settings.data_dir,settings.logs_dir)
            state={"hunt_id":"HUNT-RESUME","objective":"Hunt PowerShell","status":"partial",
                "started_epoch":0,"completed_leads":[],"lead_catalog":[],"coverage":{}}
            first_id,_=register_search_task(state,_proposal(query_spec={"query":{"term":{"case":"first"}}}))
            second_id,_=register_search_task(state,_proposal(query_spec={"query":{"term":{"case":"second"}}}))
            begin_search_task(state,first_id,now="2026-10-12T10:00:00Z")
            store.save_state(state["hunt_id"],state)

            class Snapshot:
                next=("pivot",)
            class Connection:
                def close(self): pass
            class App:
                def __init__(self): self.updated=None
                def get_state(self,config): return Snapshot()
                def update_state(self,config,value): self.updated=copy.deepcopy(value)
                def invoke(self,value,config=None):
                    self_test.assertIsNone(value)
                    self_test.assertEqual(self.updated["scheduler_migration_version"],1)
                    self_test.assertEqual(self.updated["search_queue"],[second_id,first_id])
                    self_test.assertEqual(self.updated["search_tasks"][first_id]["status"],"interrupted")
                    return copy.deepcopy(self.updated)
            self_test=self; app=App(); engine=HuntEngine(settings,store,use_ollama=False)
            with patch.object(engine,"_graph",return_value=(app,Connection())), \
                    patch("romulus.retention.apply_retention",side_effect=lambda store,state,**kwargs:state):
                result=engine.run(state["objective"],hunt_id=state["hunt_id"],_resume=True)

            self.assertEqual(result["scheduler_migration_version"],1)
            self.assertTrue(result["search_outcomes"][-1]["possible_duplicate_execution"])


if __name__ == "__main__":
    unittest.main()
