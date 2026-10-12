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
    def test_elasticsearch_task_uses_exact_scope_and_returns_own_outcome(self):
        class Elasticsearch:
            def __init__(self):
                self.calls = []

            def search_many(self, indices, query, size):
                self.calls.append((indices, query, size))
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
                    "capped": False,
                    "timed_out": False,
                    "shard_failures": 0,
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
            indices, query, size = elasticsearch.calls[0]
            self.assertEqual(indices, ["host-events"])
            self.assertEqual(query, task["query_spec"]["query"])
            self.assertEqual(size, 5)
            self.assertEqual(len(state["host"]), 1)
            self.assertEqual(state["pivot_results"], pivots_before)
            self.assertEqual(outcome["task_id"], task["task_id"])
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(outcome["returned_total"], 1)
            self.assertEqual(outcome["matched_total"], 1)
            self.assertFalse(outcome["capped"])
            self.assertFalse(outcome["timed_out"])
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))
            self.assertEqual(outcome["time_range"], task["time_range"])


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

    def search_many(self, indices, query, size):
        self.order.append("host")
        self.calls.append((indices, query, size))
        return {
            "hits": [],
            "total": 0,
            "capped": False,
            "timed_out": False,
            "shard_failures": 0,
        }


class _RecordingArkime:
    def __init__(self, order):
        self.order = order
        self.calls = []

    def search_sessions(self, expression, **kwargs):
        self.order.append("network")
        self.calls.append((expression, kwargs))
        return {"sessions": [], "total": 0}


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
            coverage_task = next(item for item in selected if item["origin"] == "coverage_frontier")
            self.assertEqual(model_task["priority_tier"], 3)
            self.assertLess(selected.index(model_task), selected.index(coverage_task))

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
    def test_arkime_task_uses_bounded_expression_and_adds_network_evidence(self):
        class Arkime:
            def __init__(self):
                self.calls = []

            def search_sessions(self, expression, **kwargs):
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
            self.assertEqual(parameters["length"], 5)
            self.assertIsNotNone(parameters["start_ms"])
            self.assertIsNotNone(parameters["stop_ms"])
            self.assertEqual(len(state["network"]), 1)
            self.assertEqual(outcome["task_id"], task["task_id"])
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(outcome["matched_total"], 1)
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
            self.assertEqual(len(state["network"]), 1)
            self.assertEqual(outcome["status"], "partial")
            self.assertEqual(outcome["returned_total"], 1)
            self.assertEqual(outcome["matched_total"], 2)
            self.assertTrue(outcome["capped"])
            self.assertTrue(outcome["artifact_id"].startswith("SR-"))

    def test_adapter_error_returns_bounded_failed_outcome(self):
        class FailingElasticsearch:
            def search_many(self, indices, query, size):
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
