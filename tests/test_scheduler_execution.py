import copy
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from romulus.config import Settings
from romulus.store import Store


def _engine(root, *, pcap_files=()):
    from romulus.investigation.workflow import HuntEngine

    config = replace(
        Settings.from_env(),
        home=root,
        data_dir=root / "data",
        logs_dir=root / "logs",
        reports_dir=root / "reports",
        es_index_patterns=("host-*",),
        arkime_username="test-user",
        arkime_password="test-value",
        arkime_max_results=5,
        pcap_allowed_dirs=(root,),
        pcap_files=tuple(pcap_files),
        max_results=5,
        max_tool_calls=20,
        historical_search=False,
    )
    return HuntEngine(config, Store(config.data_dir, config.logs_dir), use_ollama=False)


def _state():
    return {
        "hunt_id": "HUNT-SCHEDULED-EXECUTION",
        "objective": "Hunt from 2024-11-13T10:58:00Z to 2024-11-13T11:10:00Z",
        "started_epoch": time.time(),
        "tool_calls": 0,
        "tool_runs": [],
        "source_errors": [],
        "search_artifacts": [],
        "evidence_keys": [],
        "coverage": {},
        "host": [],
        "network": [],
        "queries": [],
        "pivot_results": [{"lead_id": "UNRELATED", "returned": 77}],
        "es_indices": ["host-events"],
        "es_fields": ["@timestamp", "process.name", "host.name"],
        "es_fields_by_class": {
            "host": ["@timestamp", "process.name", "host.name"],
            "network": [],
        },
    }


def _task(state, **overrides):
    from romulus.investigation.scheduler import register_search_task

    proposal = {
        "source": "elasticsearch",
        "source_family": "host",
        "source_targets": ["host-events"],
        "phase": "investigation",
        "origin": "candidate_follow_up",
        "intent": "Test one exact scheduled search",
        "query_spec": {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "2024-11-13T10:58:00Z",
                                    "lte": "2024-11-13T11:10:00Z",
                                }
                            }
                        },
                        {"term": {"process.name": "powershell.exe"}},
                    ]
                }
            },
            "size": 5,
        },
        "time_range": {
            "start": "2024-11-13T10:58:00Z",
            "end": "2024-11-13T11:10:00Z",
            "scope": "explicit mission range",
        },
        "candidate_ids": ["CL-001"],
        "follow_up_ids": ["FU-001"],
        "hypothesis_ids": ["H-001"],
        "anchor_evidence_ids": ["EV-ANCHOR"],
    }
    proposal.update(overrides)
    task_id, _ = register_search_task(state, proposal)
    return copy.deepcopy(state["search_tasks"][task_id])


class _DenyAdapter:
    def __getattr__(self, name):
        raise AssertionError(f"unexpected adapter access: {name}")


class SchedulerExecutionTests(unittest.TestCase):
    def _routing_fixture(self,directory):
        engine=_engine(Path(directory))
        state=_state()
        state.update({"mission_mode":"directed","candidate_leads":[],"hypotheses":[],
            "depth":0,"stagnant_cycles":0,"coverage":{"hypothesis_coverage":{"closure_ready":False}}})
        return engine,state

    def test_shared_router_drains_critical_and_high_work_before_stagnation(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._routing_fixture(directory)
            _task(state,candidate_priority="high")
            state["stagnant_cycles"]=engine.settings.max_stagnant_cycles

            self.assertEqual(engine._route_investigation(state,just_reasoned=False),"pivot")
            self.assertNotIn("termination_reason",state)

    def test_shared_router_reasons_once_ahead_of_low_value_breadth(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._routing_fixture(directory)
            _task(state)

            self.assertEqual(engine._route_investigation(state,just_reasoned=False),"reason")
            self.assertNotIn("termination_reason",state)

    def test_shared_router_stops_low_value_breadth_after_stagnation_threshold(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._routing_fixture(directory)
            _task(state,origin="coverage_frontier")
            state["stagnant_cycles"]=engine.settings.max_stagnant_cycles

            self.assertEqual(engine._route_investigation(state,just_reasoned=False),"report")
            self.assertEqual(state["termination_reason"],"no_productive_frontier")

    def test_shared_router_does_not_force_minimum_reasoning_rounds(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._routing_fixture(directory)
            state["depth"]=1
            self.assertGreater(engine.settings.min_reasoning_rounds,state["depth"])

            self.assertEqual(engine._route_investigation(state,just_reasoned=True),"report")
            self.assertEqual(state["termination_reason"],"no_productive_frontier")

    def test_valid_closure_wins_after_final_allowed_reasoning_turn(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._routing_fixture(directory)
            state["depth"]=engine.settings.max_depth
            state["coverage"]["hypothesis_coverage"]["closure_ready"]=True

            self.assertEqual(engine._route_investigation(state,just_reasoned=True),"report")
            self.assertEqual(state["termination_reason"],"coverage_closure_reached")

    def _progress_cycle_fixture(self,directory):
        engine,state=self._routing_fixture(directory)
        state.update({"findings":[],"lead_catalog":[],"completed_leads":[],
            "reasoning_history":[],"stage_history":[],"source_health":{"host":True,"network":True},
            "investigation_graph":{"version":1,"nodes":[],"edges":[],"paths":[],"summary":{}}})
        state["coverage"]["search_fields"]={"elasticsearch":["@timestamp","process.name"]}
        return engine,state

    def test_analysis_and_reasoning_record_progress_before_routing(self):
        from romulus.investigation.progress import initialize_progress

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._progress_cycle_fixture(directory)
            initialize_progress(state)
            engine._analyze(state)
            self.assertEqual(state["progress_history"][-1]["stage"],"analysis")
            engine._reason(state)
            self.assertEqual(state["progress_history"][-1]["stage"],"reasoning")
            persisted=engine.store.load_state(state["hunt_id"])
            self.assertEqual(persisted["progress_history"],state["progress_history"])

    def test_model_continue_true_cannot_override_exhausted_frontier(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._progress_cycle_fixture(directory)
            state["candidate_leads"]=[{"candidate_id":"CL-GROUNDED","disposition":"observed",
                "evidence_ids":[],"follow_ups":[]}]
            state["reasoning_history"].append({"stage":"analyst_reasoning",
                "continue_investigation":True,"reasoning":"Keep going without new evidence."})
            action=engine._after_reason(state)
            self.assertEqual(action,"report")
            self.assertEqual(state["termination_reason"],"no_productive_frontier")
            self.assertEqual(state.get("search_queue",[]),[])

    def test_nonresolving_search_without_material_change_advances_stagnation(self):
        from romulus.investigation.progress import initialize_progress

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._progress_cycle_fixture(directory)
            task=_task(state,origin="coverage_frontier")
            initialize_progress(state)
            state["search_tasks"][task["task_id"]]["status"]="partial"
            state["search_outcomes"].append({"task_id":task["task_id"],"source":"elasticsearch",
                "source_family":"host","status":"partial","matched_total":100,"returned_total":5,
                "capped":True,"timed_out":False,"shard_failures":0,"incomplete":True})
            engine._analyze(state)
            self.assertEqual(state["stagnant_cycles"],1)
            self.assertFalse(state["progress_history"][-1]["material_progress"])

    def test_material_evidence_or_closed_gap_resets_stagnation(self):
        from romulus.investigation.progress import initialize_progress

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state=self._progress_cycle_fixture(directory)
            initialize_progress(state)
            state["stagnant_cycles"]=2
            state["host"].append({"evidence_id":"EV-NEW","source":"elasticsearch",
                "observed_at":"2024-11-13T11:00:00Z","asset":"ws-01",
                "observation":"newly admitted process evidence","raw":{"process":{"name":"cmd.exe"}}})
            engine._analyze(state)
            self.assertEqual(state["stagnant_cycles"],0)
            self.assertEqual(state["progress_history"][-1]["signals"]["new_evidence"],1)

    def test_elasticsearch_task_uses_exact_scope_and_returns_own_outcome(self):
        class Elasticsearch:
            def __init__(self):
                self.calls = []

            def search_many(self, indices, query, size, **kwargs):
                self.calls.append((indices, query, size, kwargs))
                return {
                    "hits": [
                        {
                            "_index": "host-events",
                            "_id": "doc-1",
                            "@timestamp": "2024-11-13T11:00:00Z",
                            "process": {"name": "powershell.exe"},
                            "host": {"name": "ws-01"},
                        }
                    ],
                    "total": 1,
                    "total_relation": "eq",
                    "capped": False,
                    "timed_out": False,
                    "shard_failures": 0,
                    "sampling": {
                        "version": 1,
                        "strategy": "exhaustive",
                        "requested_strata": 1,
                        "covered_strata": 1,
                        "retained_by_stratum": [1],
                    },
                }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            elasticsearch = Elasticsearch()
            engine.es = elasticsearch
            engine.arkime = _DenyAdapter()
            engine.tshark = _DenyAdapter()
            state = _state()
            task = _task(state)
            pivots_before = copy.deepcopy(state["pivot_results"])

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(len(elasticsearch.calls), 1)
            indices, query, size, sampling_arguments = elasticsearch.calls[0]
            self.assertEqual(indices, ["host-events"])
            self.assertEqual(query, task["query_spec"]["query"])
            self.assertEqual(size, 5)
            self.assertEqual(
                sampling_arguments["time_range"],
                {"gte": "2024-11-13T10:58:00Z", "lte": "2024-11-13T11:10:00Z"},
            )
            self.assertEqual(sampling_arguments["timestamp_field"], "@timestamp")
            self.assertEqual(sampling_arguments["sampling"]["strategy"], "time_or_rank_stratified")
            self.assertEqual(len(state["host"]), 1)
            self.assertEqual(state["pivot_results"], pivots_before)
            self.assertEqual(outcome["task_id"], task["task_id"])
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(outcome["returned_total"], 1)
            self.assertEqual(outcome["matched_total"], 1)
            self.assertEqual(outcome["total_relation"], "eq")
            self.assertFalse(outcome["capped"])
            self.assertFalse(outcome["timed_out"])
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))
            self.assertEqual(outcome["time_range"], task["time_range"])
            self.assertEqual(outcome["sampling"]["strategy"], "exhaustive")

    def test_elasticsearch_non_exact_short_result_is_partial(self):
        class Elasticsearch:
            def search_many(self, indices, query, size, **kwargs):
                return {
                    "hits": [{"_index": "host-events", "_id": "doc-1", "@timestamp": "2024-11-13T11:00:00Z"}],
                    "total": 2,
                    "total_relation": "gte",
                    "capped": False,
                    "timed_out": False,
                    "shard_failures": 0,
                    "sampling": {"version": 1, "strategy": "exhaustive"},
                }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            engine.es = Elasticsearch()
            state = _state()
            task = _task(state)

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(outcome["status"], "partial")
            self.assertTrue(outcome["incomplete"])
            self.assertEqual(outcome["returned_total"], 1)
            self.assertEqual(outcome["matched_total"], 2)
            self.assertEqual(outcome["total_relation"], "gte")

    def test_task_embedded_sampling_policy_survives_state_policy_change(self):
        class Elasticsearch:
            def __init__(self):
                self.sampling = None

            def search_many(self, indices, query, size, **kwargs):
                self.sampling = kwargs["sampling"]
                return {"hits": [], "total": 0, "total_relation": "eq", "capped": False,
                    "timed_out": False, "shard_failures": 0,
                    "sampling": {"version": 1, "strategy": "exhaustive"}}

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            elasticsearch = Elasticsearch()
            engine.es = elasticsearch
            state = _state()
            state["sampling_policy"] = {"version": 1, "strategy": "time_or_rank_stratified", "strata": 3}
            task = _task(state)
            state["sampling_policy"] = {"version": 1, "strategy": "time_or_rank_stratified", "strata": 9}

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(elasticsearch.sampling["strata"], 3)

    def test_report_derives_resource_limit_from_scheduler_not_legacy_queue(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            engine = _engine(root)
            state = _state()
            state.update({
                "status": "running",
                "outcome": "pending",
                "hypotheses": [],
                "findings": [],
                "correlations": [],
                "stage_history": [],
                "source_health": {"host": True, "network": True},
            })
            state["coverage"].update({"host": "searched", "network": "searched"})
            _task(state)

            with patch("romulus.reporting.report.generate_report", return_value=[]):
                engine._report(state)

            self.assertEqual(state["termination_reason"], "resource_limit")

    def test_partial_report_never_claims_coverage_closure(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            state = _state()
            state.update({"status": "running", "outcome": "pending", "hypotheses": [],
                "findings": [], "correlations": [], "stage_history": [],
                "source_health": {"host": True, "network": True},
                "source_errors": [{"tool": "elasticsearch.search", "error": "TimeoutError"}]})
            state["coverage"].update({"host": "searched", "network": "searched"})

            with patch("romulus.reporting.report.generate_report", return_value=[]):
                engine._report(state)

            self.assertEqual(state["status"], "partial")
            self.assertFalse(state["coverage"]["coverage_closure_ready"])

    def test_stagnation_report_remains_partial_when_coverage_is_open(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory))
            state=_state()
            state.update({"status":"running","outcome":"pending","termination_reason":"no_productive_frontier",
                "hypotheses":[],"findings":[],"correlations":[],"stage_history":[],
                "source_health":{"host":True,"network":True},"stagnant_cycles":3,
                "progress_history":[
                    {"stage":"analysis","material_progress":True,"signals":{"new_evidence":1},"stagnant_cycles":0},
                    {"stage":"reasoning","material_progress":False,"signals":{},"stagnant_cycles":1},
                    {"stage":"analysis","material_progress":False,"signals":{},"stagnant_cycles":2},
                    {"stage":"reasoning","material_progress":False,"signals":{},"stagnant_cycles":3},
                ]})
            state["coverage"].update({"host":"searched","network":"searched",
                "hypothesis_coverage":{"closure_ready":False,"rows":[{"hypothesis_id":"H-OPEN","closed":False}]}})
            with patch("romulus.reporting.report.generate_report",return_value=[]):
                engine._report(state)

            self.assertEqual(state["status"],"partial")
            self.assertFalse(state["coverage"]["coverage_closure_ready"])
            self.assertEqual(state["coverage"]["progress_summary"]["final_stop_basis"],"no_productive_frontier")
            self.assertEqual(state["coverage"]["progress_summary"]["productive_cycles"],1)
            self.assertEqual(state["coverage"]["progress_summary"]["current_stagnant_cycles"],3)


def _analytic():
    return {
        "id": "BH-TEST-DISCOVERY",
        "version": 1,
        "title": "Test command behavior",
        "description": "Bounded discovery fixture.",
        "enabled": True,
        "platforms": ["cross-platform"],
        "categories": ["execution"],
        "source": "elasticsearch",
        "required_roles": ["process.command_line"],
        "optional_roles": [],
        "match": {
            "all": [
                {
                    "role": "process.command_line",
                    "operator": "contains_any",
                    "values": ["test-command"],
                }
            ],
            "any": [],
            "none": [],
        },
        "base_priority": 20,
        "specificity": 30,
        "expected_noise": "high",
        "attack_techniques": ["T1059"],
        "benign_explanations": ["Authorized testing."],
        "required_corroboration": ["Independent suspicious behavior."],
        "follow_up": ["Review process context."],
        "provenance": [{"name": "test", "url": "https://example.test/rule"}],
        "review_date": "2026-10-12",
    }


def _discovery_state():
    state = _state()
    state.update(
        {
            "status": "running",
            "mission_mode": "undirected",
            "hypotheses": [],
            "timestamp_field": "@timestamp",
            "es_fields": [
                "@timestamp",
                "message",
                "process.name",
                "process.executable",
                "process.command_line",
                "host.name",
                "source.ip",
                "destination.ip",
            ],
        }
    )
    state["es_fields_by_class"] = {"host": list(state["es_fields"]), "network": []}
    return state


def _configure_discovery_catalogs(engine):
    engine.behavior_catalog = {"catalog_version": "test", "analytics": [_analytic()]}
    engine.local_indicators = {
        "indicators": [
            {
                "id": "IOC-TEST-PROCESS",
                "type": "process",
                "value": "powershell.exe",
                "confidence": 95,
            }
        ]
    }


class _RecordingElasticsearch:
    def __init__(self, order):
        self.order = order
        self.calls = []

    def search_many(self, indices, query, size, **kwargs):
        self.order.append("host")
        self.calls.append((indices, query, size))
        return {
            "hits": [],
            "total": 0,
            "total_relation": "eq",
            "capped": False,
            "timed_out": False,
            "shard_failures": 0,
        }


class _RecordingArkime:
    def __init__(self, order):
        self.order = order
        self.calls = []

    def search_sessions_sampled(self, expression, **kwargs):
        self.order.append("network")
        self.calls.append((expression, kwargs))
        return {"sessions": [], "total": 0, "capped": False,
            "sampling": {"version": 1, "strategy": "exhaustive", "requested_strata": 1,
                "covered_strata": 0, "retained_by_stratum": [0]}}


class _RecordingTShark:
    def __init__(self, order):
        self.order = order
        self.calls = []

    def inspect(self, pcap, **kwargs):
        self.order.append("network")
        self.calls.append((pcap, kwargs))
        return {
            "packets": [],
            "count": 0,
            "matched_count": 0,
            "output_capped": False,
            "provenance": {
                "pcap": str(pcap),
                "display_filter": kwargs["display_filter"],
                "fields": kwargs["fields"],
                "time_range": "explicit filter",
            },
        }


class SchedulerDiscoveryWorkflowTests(unittest.TestCase):
    def _prepared(self, root):
        pcap = root / "discovery.pcap"
        pcap.write_bytes(b"test fixture")
        engine = _engine(root, pcap_files=(pcap,))
        _configure_discovery_catalogs(engine)
        state = _discovery_state()
        return engine, state, pcap

    def test_registration_precedes_all_deterministic_evidence_execution(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine, state, pcap = self._prepared(Path(directory))
            state["mission_mode"] = "directed"
            state["hypotheses"] = [
                {
                    "hypothesis_id": "H-DIRECTED",
                    "technique_id": "T1059.001",
                    "title": "PowerShell execution",
                    "expected_host": True,
                    "expected_network": False,
                    "tactics": ["execution"],
                    "priority": 5,
                }
            ]

            registered = engine._register_discovery_tasks(state)

            self.assertTrue(registered)
            self.assertEqual(state["tool_calls"], 0)
            self.assertEqual(state["host"], [])
            self.assertEqual(state["network"], [])
            tasks = list(state["search_tasks"].values())
            self.assertTrue(any(item["origin"] == "behavior_catalog" for item in tasks))
            self.assertTrue(any(item["origin"] == "trusted_indicator" for item in tasks))
            self.assertTrue(any(item["origin"] == "directed_survey" for item in tasks))
            self.assertTrue(any(item["source"] == "arkime" for item in tasks))
            self.assertTrue(
                any(item["source"] == "tshark" and item["source_targets"] == [str(pcap)] for item in tasks)
            )

    def test_tight_directed_budget_reaches_deterministic_search_before_model_reasoning(self):
        import types
        from unittest.mock import patch

        fake_ollama=types.ModuleType("romulus.agent.ollama")
        class Ollama:
            def __init__(self,settings): pass
            def plan_hypotheses(self,*args): return []
        fake_ollama.Ollama=Ollama

        class Elasticsearch(_RecordingElasticsearch):
            def indices(self): return [{"index":"host-events"}]
            def mappings_many(self,indices):
                return {"host-events":{"mappings":{"properties":{
                    "@timestamp":{"type":"date"},"message":{"type":"text"},
                    "process":{"properties":{"name":{"type":"keyword"},
                        "command_line":{"type":"text"}}},
                    "host":{"properties":{"name":{"type":"keyword"}}},
                }}}}

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); engine.use_ollama=True
            engine.settings=replace(engine.settings,max_tool_calls=3,arkime_username="",
                arkime_password="",pcap_files=())
            _configure_discovery_catalogs(engine)
            order=[]; elasticsearch=Elasticsearch(order); engine.es=elasticsearch
            state=_state(); state.update({"objective":"Hunt PowerShell execution from 2024-11-13T10:58:00Z to 2024-11-13T11:10:00Z",
                "status":"running","outcome":"pending","hypotheses":[],"findings":[],"correlations":[],
                "lead_catalog":[],"completed_leads":[],"reasoning_history":[],"stage_history":[],
                "candidate_leads":[],"analytic_summary":{},"behavior_catalog_status":{},
                "investigation_graph":{"version":1,"nodes":[],"edges":[],"paths":[],"summary":{}}})

            with patch.dict("sys.modules",{"romulus.agent.ollama":fake_ollama}):
                engine._plan(state); engine._collect_host(state); engine._collect_network(state)
                engine._discover(state)

            self.assertFalse(any(item.get("tool")=="ollama.api.chat" for item in state["tool_runs"]))
            self.assertEqual(state["tool_calls"],3)
            self.assertEqual(len(elasticsearch.calls),1)
            self.assertTrue(any(item.get("reasoning_stage")=="scheduled_discovery_search"
                for item in state["tool_runs"]))

    def test_discovery_drain_executes_host_and_network_before_repeating_family(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine, state, _ = self._prepared(Path(directory))
            order = []
            engine.es = _RecordingElasticsearch(order)
            engine.arkime = _RecordingArkime(order)
            engine.tshark = _RecordingTShark(order)
            engine._register_discovery_tasks(state)

            engine._drain_scheduled_tasks(state, phase="discovery", limit=3)

            self.assertEqual(set(order[:2]), {"host", "network"})
            self.assertEqual(
                {item["source_family"] for item in state["search_outcomes"][:2]},
                {"host", "network"},
            )

    def test_elasticsearch_network_index_gets_a_discovery_task_without_arkime_or_pcap(self):
        from romulus.investigation.scheduler import register_search_task

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            engine = _engine(root)
            engine.settings = replace(engine.settings, arkime_username="", arkime_password="", pcap_files=())
            _configure_discovery_catalogs(engine)
            state = _discovery_state()
            state["es_indices"] = ["host-events", "logs-suricata-events"]
            state["es_indices_by_class"] = {"host": ["host-events"], "network": ["logs-suricata-events"]}
            state["es_fields_by_class"]["network"] = [
                "@timestamp", "source.ip", "destination.ip", "source.port", "destination.port",
            ]
            state["es_fields"] = sorted(set(
                state["es_fields_by_class"]["host"] + state["es_fields_by_class"]["network"]
            ))

            engine._register_discovery_tasks(state)

            network_tasks = [task for task in state["search_tasks"].values()
                if task["phase"] == "discovery" and task["source_family"] == "network"]
            self.assertEqual(len(network_tasks), 1)
            self.assertEqual(network_tasks[0]["source"], "elasticsearch")
            self.assertEqual(network_tasks[0]["source_targets"], ["logs-suricata-events"])

            proposals=engine._compile_investigation_proposals(state,{
                "source":"elasticsearch","index_class":"network","intent":"Pivot on a network address",
                "fields":["source.ip"],"ips":["10.0.0.8"],
            },"coverage_frontier")
            self.assertEqual(proposals[0]["source_targets"],["logs-suricata-events"])
            class NetworkElasticsearch(_RecordingElasticsearch):
                def search_many(self,indices,query,size,**kwargs):
                    self.order.append("network"); self.calls.append((indices,query,size))
                    return {"hits":[{"_index":"logs-suricata-events","_id":"net-1",
                        "@timestamp":"2024-11-13T11:00:00Z","source":{"ip":"10.0.0.8"},
                        "destination":{"ip":"10.0.0.9"}}],"total":1,"capped":False,
                        "total_relation":"eq","timed_out":False,"shard_failures":0}
            order=[]; elasticsearch=NetworkElasticsearch(order); engine.es=elasticsearch
            register_search_task(state,proposals[0])
            engine._drain_scheduled_tasks(state,phase="investigation")
            self.assertEqual(elasticsearch.calls[0][0],["logs-suricata-events"])
            self.assertEqual(len(state["network"]),1)
            self.assertEqual(state["host"],[])

    def test_network_only_elasticsearch_mapping_does_not_claim_host_coverage(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); engine.settings=replace(engine.settings,
                arkime_username="",arkime_password="",pcap_files=())
            _configure_discovery_catalogs(engine)
            state=_discovery_state(); state.update({
                "es_indices":["logs-suricata-events"],
                "es_indices_by_class":{"network":["logs-suricata-events"]},
                "es_fields":["@timestamp","source.ip","destination.ip"],
                "es_fields_by_class":{"network":["@timestamp","source.ip","destination.ip"]},
                "hypotheses":[{"hypothesis_id":"H-HOST","technique_id":"T1059",
                    "title":"Host command execution","priority":4,"expected_host":["process"],
                    "expected_network":[],"status":"not assessed"}],
            })

            engine._register_discovery_tasks(state)

            tasks=list(state["search_tasks"].values())
            self.assertFalse(any(task["source_family"]=="host" for task in tasks))
            self.assertTrue(any(task["source_family"]=="network" for task in tasks))
            self.assertFalse(state["source_health"]["host"])

            engine._analyze(state)
            ledger=state["coverage"]["hypothesis_coverage"]
            self.assertEqual(ledger["rows"][0]["telemetry_gaps"],["host telemetry unavailable"])

    def test_repeated_registration_reuses_one_materialized_relative_window(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            engine = _engine(root)
            engine.settings = replace(engine.settings, historical_search=False,
                arkime_username="", arkime_password="", pcap_files=())
            _configure_discovery_catalogs(engine)
            state = _discovery_state()
            state["objective"] = "Conduct a broad threat hunt"
            first = {"gte": "2026-10-11T12:00:00+00:00", "lte": "2026-10-12T12:00:00+00:00"}
            second = {"gte": "2026-10-11T12:00:01+00:00", "lte": "2026-10-12T12:00:01+00:00"}

            with patch("romulus.investigation.workflow._materialize_time_range", side_effect=[first, second]) as materialize:
                engine._register_discovery_tasks(state)
                task_count = len(state["search_tasks"])
                engine._register_discovery_tasks(state)
                first_effective, first_scope = engine._effective_task_window(state, {})
                second_effective, second_scope = engine._effective_task_window(state, {})

            self.assertEqual(materialize.call_count, 1)
            self.assertEqual(len(state["search_tasks"]), task_count)
            self.assertEqual(first_effective, second_effective)
            self.assertEqual(first_scope, second_scope)

    def test_duplicate_origins_execute_once_and_preserve_both_owners(self):
        from romulus.investigation.scheduler import register_search_task

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            calls = []
            engine.es = _RecordingElasticsearch(calls)
            state = _discovery_state()
            proposal = {
                "source": "elasticsearch",
                "source_family": "host",
                "source_targets": ["host-events"],
                "phase": "discovery",
                "origin": "behavior_catalog",
                "intent": "first owner",
                "query_spec": {
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": "2024-11-13T10:58:00Z",
                                            "lte": "2024-11-13T11:10:00Z",
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": 5,
                },
                "time_range": {
                    "start": "2024-11-13T10:58:00Z",
                    "end": "2024-11-13T11:10:00Z",
                    "scope": "explicit mission range",
                },
                "hypothesis_ids": ["H-001"],
            }
            task_id, _ = register_search_task(state, proposal)
            register_search_task(
                state,
                {
                    **proposal,
                    "origin": "directed_survey",
                    "intent": "second owner",
                    "candidate_ids": ["CL-001"],
                },
            )

            engine._drain_scheduled_tasks(state, phase="discovery")

            self.assertEqual(calls, ["host"])
            task = state["search_tasks"][task_id]
            self.assertEqual(task["origins"], ["behavior_catalog", "directed_survey"])
            self.assertEqual(task["hypothesis_ids"], ["H-001"])
            self.assertEqual(task["candidate_ids"], ["CL-001"])
            self.assertEqual(len(state["search_outcomes"]), 1)

    def test_every_registered_discovery_task_gets_one_authoritative_outcome(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine, state, _ = self._prepared(Path(directory))
            order = []
            engine.es = _RecordingElasticsearch(order)
            engine.arkime = _RecordingArkime(order)
            engine.tshark = _RecordingTShark(order)
            engine._register_discovery_tasks(state)

            engine._drain_scheduled_tasks(state, phase="discovery")

            self.assertEqual(len(state["search_outcomes"]), len(state["search_tasks"]))
            self.assertEqual(
                {item["task_id"] for item in state["search_outcomes"]},
                set(state["search_tasks"]),
            )
            fingerprints = [item["execution_fingerprint"] for item in state["search_tasks"].values()]
            self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_undirected_candidate_free_discovery_never_calls_ollama(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine, state, _ = self._prepared(Path(directory))
            engine.use_ollama = True
            order = []
            engine.es = _RecordingElasticsearch(order)
            engine.arkime = _RecordingArkime(order)
            engine.tshark = _RecordingTShark(order)

            engine._register_discovery_tasks(state)
            engine._drain_scheduled_tasks(state, phase="discovery")

            self.assertFalse(any(item.get("tool") == "ollama.api.chat" for item in state["tool_runs"]))
            self.assertEqual(state["hypotheses"], [])

    def test_budget_exhaustion_keeps_queued_tasks_and_marks_hunt_partial(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine, state, _ = self._prepared(Path(directory))
            engine.settings = replace(engine.settings, max_tool_calls=1)
            order = []
            engine.es = _RecordingElasticsearch(order)
            engine.arkime = _RecordingArkime(order)
            engine.tshark = _RecordingTShark(order)
            engine._register_discovery_tasks(state)

            engine._drain_scheduled_tasks(state, phase="discovery")

            self.assertEqual(state["status"], "partial")
            self.assertTrue(state["search_queue"])
            self.assertTrue(state["coverage"]["scheduler_gaps"])
            self.assertTrue(
                any(item.get("event") == "discovery_budget_gap" for item in state["scheduler_history"])
            )

    def test_report_terminalizes_every_unrun_task_without_remote_calls(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine,state,_=self._prepared(Path(directory))
            engine.settings=replace(engine.settings,max_tool_calls=1)
            order=[]; engine.es=_RecordingElasticsearch(order); engine.arkime=_RecordingArkime(order)
            engine.tshark=_RecordingTShark(order)
            engine._register_discovery_tasks(state)
            engine._drain_scheduled_tasks(state,phase="discovery")
            remote_calls=len(order); used_calls=state["tool_calls"]
            registered=set(state["search_tasks"])

            with patch("romulus.reporting.report.generate_report",return_value=[]):
                engine._report(state)

            self.assertEqual(len(order),remote_calls)
            self.assertEqual(state["tool_calls"],used_calls)
            self.assertEqual(state["search_queue"],[])
            outcomes={item["task_id"]:item for item in state["search_outcomes"]}
            self.assertEqual(set(outcomes),registered)
            unrun=[item for item in outcomes.values() if item["status"]=="budget_limited"]
            self.assertTrue(unrun)
            self.assertTrue(all(item["attempt_count"]==0 for item in unrun))


def _investigation_state():
    state = _discovery_state()
    state.update(
        {
            "mission_mode": "undirected",
            "depth": 1,
            "hypotheses": [
                {
                    "hypothesis_id": "H-CANDIDATE",
                    "technique_id": "T1059.001",
                    "title": "Candidate-backed execution",
                    "priority": 5,
                    "basis": "observed_candidate",
                    "basis_candidate_ids": ["CL-CRITICAL"],
                    "basis_evidence_ids": ["EV-ANCHOR"],
                    "expected_host": ["process execution"],
                    "expected_network": [],
                },
                {
                    "hypothesis_id": "H-COVERAGE",
                    "technique_id": "T1059",
                    "title": "Remaining execution coverage",
                    "priority": 3,
                    "basis": "coverage_frontier",
                    "expected_host": ["process execution"],
                    "expected_network": [],
                },
            ],
            "host": [
                {
                    "evidence_id": "EV-ANCHOR",
                    "source": "elasticsearch",
                    "observed_at": "2024-11-13T11:00:00Z",
                    "asset": "ws-01",
                    "observation": "candidate process",
                    "raw": {"process": {"name": "powershell.exe"}, "host": {"name": "ws-01"}},
                }
            ],
            "candidate_leads": [
                {
                    "candidate_id": "CL-CRITICAL",
                    "kind": "behavior",
                    "title": "Critical candidate",
                    "priority_tier": "critical",
                    "priority_score": 99,
                    "disposition": "observed",
                    "evidence_ids": ["EV-ANCHOR"],
                    "follow_ups": [
                        {
                            "follow_up_id": "FU-CRITICAL",
                            "intent": "Validate exact process context",
                            "status": "pending",
                            "history": [],
                        }
                    ],
                }
            ],
            "lead_catalog": [
                {
                    "id": "C-CANDIDATE-HOST",
                    "source": "host",
                    "intent": "Validate exact process context",
                    "hypothesis_id": "H-CANDIDATE",
                    "candidate_id": "CL-CRITICAL",
                    "follow_up_id": "FU-CRITICAL",
                    "anchor_evidence_ids": ["EV-ANCHOR"],
                    "terms": ["powershell.exe"],
                    "priority": 5,
                },
                {
                    "id": "C-COVERAGE-HOST",
                    "source": "host",
                    "intent": "Test remaining command execution coverage",
                    "hypothesis_id": "H-COVERAGE",
                    "terms": ["cmd.exe"],
                    "priority": 3,
                },
            ],
        }
    )
    state["coverage"]["search_fields"] = {
        "elasticsearch": ["process.name", "process.command_line", "@timestamp"]
    }
    return state


class SchedulerInvestigationWorkflowTests(unittest.TestCase):
    def test_model_finding_requires_a_supported_hypothesis_and_two_matching_records(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); state=_investigation_state()
            state["findings"]=[]
            state["network"]=[
                {"evidence_id":"EV-FLOW-1","source":"tshark","observed_at":"2024-11-13T11:00:00Z",
                    "raw":{"ip.src":"172.17.100.252","ip.dst":"185.125.190.81","tcp.dstport":"80"}},
                {"evidence_id":"EV-OTHER","source":"arkime","observed_at":"2024-11-13T11:00:01Z",
                    "raw":{"source":{"ip":"172.17.100.252"},"destination":{"ip":"18.239.236.88","port":443}}},
                {"evidence_id":"EV-FLOW-2","source":"elasticsearch","observed_at":"2024-11-13T11:00:02Z",
                    "raw":{"source":{"ip":"172.17.100.252"},"destination":{"ip":"185.125.190.81","port":80}}},
            ]
            hypothesis=state["hypotheses"][0]
            hypothesis.update({"technique_id":"T1046","status":"supported lead",
                "model_assessment":{"status":"supported","evidence_ids":["EV-FLOW-1","EV-OTHER","EV-FLOW-2"]}})
            proposal={"hypothesis_id":hypothesis["hypothesis_id"],
                "title":"Outbound traffic to 185.125.190.81","technique_id":"T1046",
                "observation":"172.17.100.252 connected to 185.125.190.81 on port 80.",
                "interpretation":"This repeated flow warrants benign-alternative review.",
                "evidence_ids":["EV-FLOW-1","EV-OTHER","EV-FLOW-2"],"confidence":"high",
                "confidence_justification":"Three records were cited.",
                "alternatives":["Expected software update traffic."],"follow_up":["Identify the owning process."]}

            engine._publish_model_findings(state,[proposal],set(proposal["evidence_ids"]))

            self.assertEqual(len(state["findings"]),1)
            self.assertEqual(state["findings"][0]["evidence_ids"],["EV-FLOW-1","EV-FLOW-2"])
            self.assertEqual(state["findings"][0]["confidence"],"moderate")
            self.assertNotIn("172.17.100.252 connected",state["findings"][0]["observation"])
            self.assertIn(hypothesis["title"],state["findings"][0]["observation"])

    def test_model_finding_rejects_unsupported_attack_mapping_and_single_record_claim(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); state=_investigation_state()
            state["findings"]=[]
            state["network"]=[
                {"evidence_id":"EV-FLOW","source":"tshark","observed_at":"2024-11-13T11:00:00Z",
                    "raw":{"ip.src":"172.17.100.252","ip.dst":"185.125.190.81","tcp.dstport":"80"}},
                {"evidence_id":"EV-DNS","source":"elasticsearch","observed_at":"2024-11-13T11:00:01Z",
                    "raw":{"source":{"ip":"172.17.100.252"},"destination":{"ip":"172.17.100.254","port":53}}},
            ]
            hypothesis=state["hypotheses"][0]
            hypothesis.update({"technique_id":"T1046","status":"supported lead",
                "model_assessment":{"status":"supported","evidence_ids":["EV-FLOW","EV-DNS"]}})
            base={"hypothesis_id":hypothesis["hypothesis_id"],
                "title":"Outbound traffic to 185.125.190.81",
                "observation":"172.17.100.252 connected to 185.125.190.81 on port 80.",
                "interpretation":"This flow may merit further review.","evidence_ids":["EV-FLOW","EV-DNS"],
                "confidence":"high","confidence_justification":"Two records were cited.",
                "alternatives":["Expected software update traffic."],"follow_up":["Identify the owning process."]}

            engine._publish_model_findings(state,[{**base,"technique_id":"T1110"}],set(base["evidence_ids"]))
            engine._publish_model_findings(state,[{**base,"technique_id":"T1046"}],set(base["evidence_ids"]))

            self.assertEqual(state["findings"],[])

    def test_supported_model_assessment_is_downgraded_when_citations_miss_candidate_entity(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); state=_investigation_state()
            state["network"]=[{"evidence_id":"EV-UNRELATED","source":"arkime",
                "raw":{"source":{"ip":"10.0.0.50"},"destination":{"ip":"10.0.0.60"}}}]

            engine._apply_model_assessments(state,{"assessments":[{
                "hypothesis_id":"H-CANDIDATE","status":"supported",
                "evidence_ids":["EV-UNRELATED"],"rationale":"This proves the candidate."}]},{"EV-UNRELATED"})

            self.assertEqual(state["hypotheses"][0]["model_assessment"]["status"],"inconclusive")
            self.assertEqual(state["hypotheses"][0]["model_assessment"]["evidence_ids"],[])

    def test_model_search_with_malformed_ipv4_in_intent_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); state=_investigation_state()
            raw={"source":"elasticsearch","hypothesis_id":"H-CANDIDATE",
                "candidate_id":"CL-CRITICAL","follow_up_id":"FU-CRITICAL",
                "intent":"Correlate 172.17.10,0.252 with 185.125.190.81",
                "fields":["process.name"],"terms":[],"ips":["185.125.190.81"],
                "hostnames":[],"ports":[],"protocols":[],"event_codes":[],
                "index_class":"host","anchor_evidence_ids":["EV-ANCHOR"],
                "native_query_language":"none","native_query":""}

            accepted=engine._register_model_searches(state,[raw],"iterative")

            self.assertEqual(accepted,[])
            self.assertEqual(state["coverage"]["model_search_planning"][-1]["invalid_or_unmappable"],1)

    def test_generic_network_follow_up_prefers_arkime_and_uses_pcaps_only_as_fallback(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root=Path(directory); captures=(root/"one.pcap",root/"two.pcap")
            engine=_engine(root,pcap_files=captures); state=_state()
            lead={"source":"network","intent":"Review an anchored network candidate",
                "ips":["10.0.0.8"],"ports":[445],"protocols":["tcp"]}

            preferred=engine._compile_investigation_proposals(state,lead,"candidate_follow_up")

            self.assertEqual([item["source"] for item in preferred],["arkime"])

            engine.settings=replace(engine.settings,arkime_username="",arkime_password="")
            fallback=engine._compile_investigation_proposals(state,lead,"candidate_follow_up")
            self.assertEqual([item["source"] for item in fallback],["tshark","tshark"])
            self.assertEqual({item["source_targets"][0] for item in fallback},{str(path) for path in captures})

    def test_grounded_reasoning_runs_after_high_candidate_work_and_before_breadth(self):
        from romulus.investigation.scheduler import register_search_task

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); engine.use_ollama=True
            engine.settings=replace(engine.settings,max_tool_calls=10,max_depth=4)
            state=_investigation_state(); state.update({"depth":0,"lead_catalog":[],"tool_calls":2})
            base={"source":"elasticsearch","source_family":"host","source_targets":["host-events"],
                "phase":"investigation","intent":"Test queued work",
                "query_spec":{"query":{"match":{"process.name":"cmd.exe"}},"size":5},
                "time_range":{"start":"2024-11-13T10:58:00Z","end":"2024-11-13T11:10:00Z"},
                "candidate_ids":[],"follow_up_ids":[],"hypothesis_ids":[],"anchor_evidence_ids":[]}
            register_search_task(state,{**base,"origin":"coverage_frontier"})

            self.assertEqual(engine._after_analyze(state),"reason")

            high=_investigation_state(); high.update({"depth":0,"lead_catalog":[],"tool_calls":2})
            register_search_task(high,{**base,"origin":"candidate_follow_up",
                "candidate_ids":["CL-CRITICAL"],"follow_up_ids":["FU-CRITICAL"],
                "candidate_priority":"high"})
            self.assertEqual(engine._after_analyze(high),"pivot")

            last_call=_investigation_state(); last_call.update({"depth":0,"lead_catalog":[],"tool_calls":9})
            register_search_task(last_call,{**base,"origin":"coverage_frontier"})
            self.assertEqual(engine._after_analyze(last_call),"pivot")

    def test_late_model_owner_receives_an_already_terminal_task_outcome(self):
        from romulus.investigation.scheduler import register_search_task
        from romulus.investigation.search_planner import expand_anchor_selectors

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); state=_investigation_state(); state["lead_catalog"]=[]
            order=[]; engine.es=_RecordingElasticsearch(order)
            base={"source":"elasticsearch","hypothesis_id":"H-CANDIDATE",
                "intent":"Check exact anchored process context","fields":["process.name"],
                "terms":["powershell.exe"],"anchor_evidence_ids":["EV-ANCHOR"]}
            expanded=expand_anchor_selectors(base,state["host"])
            proposal=engine._compile_investigation_proposals(state,expanded,"coverage_frontier")[0]
            task_id,_=register_search_task(state,proposal)
            engine._pivot(state)
            self.assertEqual(state["candidate_leads"][0]["follow_ups"][0]["status"],"pending")

            model={**base,"candidate_id":"CL-CRITICAL","follow_up_id":"FU-CRITICAL"}
            accepted=engine._register_model_searches(state,[model],"iterative")

            self.assertEqual(accepted[0]["task_id"],task_id)
            follow_up=state["candidate_leads"][0]["follow_ups"][0]
            self.assertEqual(follow_up["status"],"completed")
            self.assertEqual(follow_up["history"][-1]["task_id"],task_id)
            self.assertEqual(len(order),1)

    def test_initial_model_planning_cannot_spend_the_last_call_before_queued_work(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); engine.use_ollama=True
            engine.settings=replace(engine.settings,max_tool_calls=5)
            state=_investigation_state(); state["mission_mode"]="directed"; state["tool_calls"]=4

            registered=engine._register_directed_initial_tasks(state)

            self.assertTrue(registered)
            self.assertFalse(any(item.get("tool")=="ollama.api.chat" for item in state["tool_runs"]))
            self.assertEqual(state["coverage"]["model_initial_search_plan"]["status"],
                "deferred: execution capacity reserved for queued searches")

    def test_initial_model_planning_defers_for_a_possible_multipage_arkime_task(self):
        from romulus.investigation.scheduler import register_search_task

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); engine.use_ollama=True
            engine.settings=replace(engine.settings,max_tool_calls=6,arkime_max_results=3000)
            state=_investigation_state(); state.update({"mission_mode":"directed","tool_calls":4,
                "lead_catalog":[]})
            register_search_task(state,{"source":"arkime","source_family":"network",
                "source_targets":[engine.settings.arkime_url],"phase":"investigation",
                "origin":"directed_survey","intent":"Review a bounded Arkime result set",
                "query_spec":{"expression":"protocols == tcp","cap":3000},
                "time_range":{"start":"2024-11-13T10:58:00Z","end":"2024-11-13T11:10:00Z"}})

            engine._register_directed_initial_tasks(state)

            self.assertFalse(any(item.get("tool")=="ollama.api.chat" for item in state["tool_runs"]))
            plan=state["coverage"]["model_initial_search_plan"]
            self.assertEqual(plan["status"],"deferred: execution capacity reserved for queued searches")
            self.assertEqual(plan["remaining_tool_calls"],2)

    def test_candidate_model_and_coverage_share_fixed_priority_queue(self):
        from romulus.investigation.scheduler import select_search_tasks

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            state = _investigation_state()
            model = {
                "source": "elasticsearch",
                "hypothesis_id": "H-CANDIDATE",
                "candidate_id": "CL-CRITICAL",
                "follow_up_id": "FU-CRITICAL",
                "intent": "Check anchored sibling execution",
                "fields": ["process.name"],
                "terms": ["wscript.exe"],
                "anchor_evidence_ids": ["EV-ANCHOR"],
                "priority_tier": -100,
                "priority_score": 999999,
            }

            accepted = engine._register_model_searches(state, [model], "iterative")
            engine._register_investigation_tasks(state)
            selected = select_search_tasks(state, phase="investigation", limit=10)

            self.assertTrue(accepted)
            self.assertEqual(selected[0]["origin"], "candidate_follow_up")
            model_task = next(item for item in selected if item["origin"] == "model_proposal")
            merged_task = selected[0]
            self.assertEqual(merged_task["origins"], ["candidate_follow_up", "coverage_frontier"])
            self.assertEqual(set(merged_task["hypothesis_ids"]), {"H-CANDIDATE", "H-COVERAGE"})
            self.assertEqual(merged_task["priority_tier"], 1)
            self.assertEqual(model_task["priority_tier"], 3)
            self.assertLess(selected.index(merged_task), selected.index(model_task))

    def test_model_search_with_invisible_candidate_or_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            state = _investigation_state()
            proposal = {
                "source": "elasticsearch",
                "hypothesis_id": "H-CANDIDATE",
                "candidate_id": "CL-INVISIBLE",
                "intent": "Search an ungrounded entity",
                "fields": ["process.name"],
                "terms": ["rundll32.exe"],
                "anchor_evidence_ids": ["EV-INVISIBLE"],
            }

            accepted = engine._register_model_searches(state, [proposal], "iterative")

            self.assertEqual(accepted, [])
            self.assertFalse(
                any(task.get("origin") == "model_proposal" for task in state.get("search_tasks", {}).values())
            )

    def test_merged_candidate_owners_receive_the_same_exact_outcome(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            state = _investigation_state()
            second = copy.deepcopy(state["candidate_leads"][0])
            second["candidate_id"] = "CL-SECOND"
            second["follow_ups"][0]["follow_up_id"] = "FU-SECOND"
            state["candidate_leads"].append(second)
            duplicate = copy.deepcopy(state["lead_catalog"][0])
            duplicate.update(
                {
                    "id": "C-SECOND-HOST",
                    "candidate_id": "CL-SECOND",
                    "follow_up_id": "FU-SECOND",
                }
            )
            state["lead_catalog"].append(duplicate)
            calls = []
            engine.es = _RecordingElasticsearch(calls)

            engine._register_investigation_tasks(state)
            candidate_tasks = [
                item
                for item in state["search_tasks"].values()
                if item.get("origin") == "candidate_follow_up"
            ]
            self.assertEqual(len(candidate_tasks), 1)
            task_id = candidate_tasks[0]["task_id"]

            engine._pivot(state)

            self.assertEqual(calls, ["host"])
            for candidate in state["candidate_leads"]:
                follow_up = candidate["follow_ups"][0]
                self.assertEqual(follow_up["status"], "completed")
                self.assertEqual(follow_up["history"][-1]["task_id"], task_id)
                self.assertEqual(follow_up["history"][-1]["returned"], 0)

    def test_model_task_uses_its_own_outcome_not_an_older_pivot_row(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            state = _investigation_state()
            state["lead_catalog"] = []
            state["pivot_results"] = [
                {"lead_id": "OLD-STATIC", "status": "failed query", "returned": 77}
            ]
            calls = []
            engine.es = _RecordingElasticsearch(calls)
            proposal = {
                "source": "elasticsearch",
                "hypothesis_id": "H-CANDIDATE",
                "candidate_id": "CL-CRITICAL",
                "follow_up_id": "FU-CRITICAL",
                "intent": "Check exact anchored process context",
                "fields": ["process.name"],
                "terms": ["powershell.exe"],
                "anchor_evidence_ids": ["EV-ANCHOR"],
            }
            engine._register_model_searches(state, [proposal], "iterative")

            engine._pivot(state)

            follow_up = state["candidate_leads"][0]["follow_ups"][0]
            self.assertEqual(follow_up["status"], "completed")
            self.assertEqual(follow_up["history"][-1]["returned"], 0)
            self.assertTrue(follow_up["history"][-1]["task_id"].startswith("ST-"))
            self.assertEqual(state["pivot_results"][0]["returned"], 77)


class SchedulerExecutionAdditionalTests(unittest.TestCase):
    def test_pending_legacy_lead_is_compiled_before_execution(self):
        from romulus.investigation.scheduler import migrate_legacy_search_state

        class Elasticsearch:
            def __init__(self): self.calls=[]
            def search_many(self,indices,query,size,**kwargs):
                self.calls.append((indices,query,size))
                return {"hits":[],"total":0,"total_relation":"eq","capped":False,
                    "timed_out":False,"shard_failures":0}

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine=_engine(Path(directory)); elasticsearch=Elasticsearch(); engine.es=elasticsearch
            state=_state()
            state.update({"completed_leads":[],"hypotheses":[{"hypothesis_id":"H-LEGACY"}],
                "lead_catalog":[{"id":"C-LEGACY","source":"host","intent":"Find rundll32 execution",
                    "terms":["rundll32"],"hypothesis_id":"H-LEGACY"}]})

            migrate_legacy_search_state(state,compile_pending=lambda lead:
                engine._compile_investigation_proposals(state,lead,"coverage_frontier"))
            engine._drain_scheduled_tasks(state,phase="investigation")

            self.assertEqual(len(elasticsearch.calls),1)
            task=next(iter(state["search_tasks"].values()))
            self.assertIn("query",task["query_spec"])
            self.assertEqual(task["legacy_lead_id"],"C-LEGACY")
            self.assertEqual(state["search_outcomes"][0]["status"],"completed")

    def test_arkime_task_uses_bounded_expression_and_adds_network_evidence(self):
        class Arkime:
            def __init__(self):
                self.calls = []

            def search_sessions_sampled(self, expression, **kwargs):
                self.calls.append((expression, kwargs))
                return {
                    "sessions": [
                        {
                            "id": "session-1",
                            "source.ip": "10.0.0.5",
                            "destination.ip": "10.0.0.8",
                            "destination.port": 445,
                            "firstPacket": 1731513600,
                        }
                    ],
                    "total": 1,
                    "capped": False,
                    "requests": 2,
                    "pages": 1,
                    "sampling": {
                        "version": 1,
                        "strategy": "exhaustive",
                        "requested_strata": 1,
                        "covered_strata": 1,
                        "retained_by_stratum": [1],
                    },
                }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            arkime = Arkime()
            engine.es = _DenyAdapter()
            engine.arkime = arkime
            engine.tshark = _DenyAdapter()
            state = _state()
            task = _task(
                state,
                source="arkime",
                source_family="network",
                source_targets=[engine.settings.arkime_url],
                query_spec={"expression": "ip.dst == 10.0.0.8", "cap": 5},
            )

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(len(arkime.calls), 1)
            expression, parameters = arkime.calls[0]
            self.assertEqual(expression, "ip.dst == 10.0.0.8")
            self.assertEqual(parameters["limit"], 5)
            self.assertIsNotNone(parameters["start_ms"])
            self.assertIsNotNone(parameters["stop_ms"])
            self.assertEqual(parameters["sampling"]["strategy"], "time_or_rank_stratified")
            self.assertEqual(len(state["network"]), 1)
            self.assertEqual(outcome["task_id"], task["task_id"])
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(outcome["matched_total"], 1)
            self.assertEqual(outcome["sampling"]["strategy"], "exhaustive")
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))

    def test_one_capture_tshark_task_reports_cap_as_partial(self):
        class TShark:
            def __init__(self):
                self.calls = []

            def inspect(self, pcap, **kwargs):
                self.calls.append((Path(pcap), kwargs))
                return {
                    "packets": [
                        {
                            "frame.number": "1",
                            "frame.time_epoch": "1731513600",
                            "ip.src": "10.0.0.5",
                            "ip.dst": "10.0.0.8",
                        }
                    ],
                    "count": 1,
                    "matched_count": 2,
                    "output_capped": True,
                    "sampling": {
                        "version": 1,
                        "strategy": "time_stratified_reservoir",
                        "requested_strata": 1,
                        "covered_strata": 1,
                        "retained_by_stratum": [1],
                    },
                    "provenance": {
                        "pcap": str(pcap),
                        "display_filter": kwargs["display_filter"],
                        "fields": kwargs["fields"],
                        "time_range": "explicit filter",
                    },
                }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"test fixture")
            engine = _engine(root, pcap_files=(pcap,))
            tshark = TShark()
            engine.es = _DenyAdapter()
            engine.arkime = _DenyAdapter()
            engine.tshark = tshark
            state = _state()
            task = _task(
                state,
                source="tshark",
                source_family="network",
                source_targets=[str(pcap)],
                query_spec={
                    "display_filter": "ip.dst == 10.0.0.8",
                    "fields": ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"],
                    "limit": 1,
                },
            )

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(len(tshark.calls), 1)
            called_pcap, parameters = tshark.calls[0]
            self.assertEqual(called_pcap, pcap)
            self.assertEqual(parameters["limit"], 1)
            self.assertIn("frame.time_epoch >=", parameters["time_filter"])
            self.assertIsNotNone(parameters["sample_start"])
            self.assertIsNotNone(parameters["sample_end"])
            self.assertEqual(parameters["sampling"]["strategy"], "time_or_rank_stratified")
            self.assertEqual(len(state["network"]), 1)
            self.assertEqual(outcome["status"], "partial")
            self.assertEqual(outcome["returned_total"], 1)
            self.assertEqual(outcome["matched_total"], 2)
            self.assertTrue(outcome["capped"])
            self.assertEqual(outcome["sampling"]["strategy"], "time_stratified_reservoir")
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))

    def test_adapter_error_returns_bounded_failed_outcome(self):
        class FailingElasticsearch:
            def search_many(self, indices, query, size, **kwargs):
                raise RuntimeError("source unavailable " + ("x" * 1000))

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory))
            engine.es = FailingElasticsearch()
            state = _state()
            task = _task(state)

            outcome = engine._execute_search_task(state, task)

            self.assertEqual(outcome["task_id"], task["task_id"])
            self.assertEqual(outcome["status"], "failed")
            self.assertEqual(outcome["error_kind"], "RuntimeError")
            self.assertLessEqual(len(outcome["reason"]), 300)
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))


if __name__ == "__main__":
    unittest.main()
