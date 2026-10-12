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
