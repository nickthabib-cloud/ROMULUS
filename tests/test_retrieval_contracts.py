import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from romulus.config import Settings
from romulus.store import Store


def _mapping(properties):
    return {"mixed-events": {"mappings": {"properties": properties}}}


def _engine(root, mapping):
    from romulus.investigation.workflow import HuntEngine

    settings = replace(
        Settings.from_env(),
        home=root,
        data_dir=root / "data",
        logs_dir=root / "logs",
        reports_dir=root / "reports",
        es_index_patterns=("mixed-*",),
        arkime_username="",
        arkime_password="",
        pcap_allowed_dirs=(),
        pcap_files=(),
        max_tool_calls=40,
        historical_search=False,
    )
    engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), use_ollama=False)

    class Elasticsearch:
        def indices(self):
            return [{"index": "mixed-events"}]

        def mappings_many(self, indices):
            return mapping

    engine.es = Elasticsearch()
    engine._call = lambda state, tool, stage, parameters, scope, function, count: function()
    return engine


def _inventory_state():
    return {
        "hunt_id": "HUNT-MIXED-INVENTORY",
        "objective": "Hunt from 2026-02-01T00:00:00Z to 2026-02-01T01:00:00Z",
        "started_epoch": time.time(),
        "tool_calls": 0,
        "coverage": {},
        "source_health": {},
        "stage_history": [],
        "hypotheses": [],
    }


class MixedIndexClassificationTests(unittest.TestCase):
    def test_field_capabilities_survive_the_langgraph_node_boundary(self):
        try:
            from langgraph.graph import END, StateGraph
        except ModuleNotFoundError:
            self.skipTest("langgraph dependency is not installed")
        from romulus.investigation.workflow import HuntState

        mapping = _mapping({
            "@timestamp": {"type": "date"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {"command_line": {"type": "text"}}},
        })
        seen = {}
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), mapping)

            def observe(state):
                seen.update({
                    "global": state.get("es_field_capabilities"),
                    "classified": state.get("es_field_capabilities_by_class"),
                })
                return state

            graph = StateGraph(HuntState)
            graph.add_node("collect", engine._collect_host)
            graph.add_node("observe", observe)
            graph.set_entry_point("collect")
            graph.add_edge("collect", "observe")
            graph.add_edge("observe", END)
            graph.compile().invoke(_inventory_state())

        self.assertEqual(seen["global"]["process.command_line"], ["text"])
        self.assertEqual(seen["classified"]["host"]["process.command_line"], ["text"])

    def test_mapping_capabilities_keep_only_queryable_leaf_fields_and_multifields(self):
        from romulus.investigation.workflow import _field_capabilities, _field_capabilities_by_class

        mapping = _mapping({
            "@timestamp": {"type": "date"},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "process": {"type": "object", "properties": {
                "command_line": {"type": "wildcard"},
            }},
            "nested_events": {"type": "nested", "properties": {
                "value": {"type": "keyword"},
            }},
            "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        })

        capabilities = _field_capabilities(mapping)
        classified = _field_capabilities_by_class(mapping)

        self.assertNotIn("user", capabilities)
        self.assertNotIn("process", capabilities)
        self.assertNotIn("nested_events", capabilities)
        self.assertNotIn("nested_events.value", capabilities)
        self.assertEqual(capabilities["@timestamp"], ["date"])
        self.assertEqual(capabilities["user.name"], ["keyword"])
        self.assertEqual(capabilities["process.command_line"], ["wildcard"])
        self.assertEqual(capabilities["message"], ["text"])
        self.assertEqual(capabilities["message.keyword"], ["keyword"])
        self.assertEqual(classified["host"]["process.command_line"], ["wildcard"])

    def test_inventory_persists_field_capabilities_and_excludes_object_containers(self):
        properties = {
            "@timestamp": {"type": "date"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}}},
            "message": {"type": "text"},
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping(properties))
            state = engine._collect_host(_inventory_state())

        self.assertNotIn("host", state["es_fields"])
        self.assertNotIn("process", state["es_fields"])
        self.assertEqual(state["es_field_capabilities"]["message"], ["text"])
        self.assertEqual(
            state["es_field_capabilities_by_class"]["host"]["process.name"],
            ["keyword"],
        )

    def test_legacy_resumed_inventory_refreshes_capabilities_and_invalidates_untyped_tasks(self):
        properties = {
            "@timestamp": {"type": "date"},
            "process": {"properties": {
                "name": {"type": "keyword"},
                "pid": {"type": "long"},
            }},
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping(properties))
            state = _inventory_state()
            state.update({
                "es_indices": ["mixed-events"],
                "es_fields": ["@timestamp", "process.name", "process.pid"],
                "search_tasks": {
                    "ST-LEGACY": {
                        "phase": "discovery", "origin": "behavior_catalog",
                        "status": "queued",
                    },
                },
                "search_queue": ["ST-LEGACY"],
            })
            engine._migrate_legacy_schema_capabilities(state)

        self.assertEqual(state["es_field_capabilities"]["process.pid"], ["long"])
        self.assertEqual(
            state["coverage"]["schema_capability_migration"]["status"],
            "refreshed",
        )
        self.assertEqual(
            state["coverage"]["schema_capability_migration"]["invalidated_untyped_tasks"],
            1,
        )
        self.assertNotIn("ST-LEGACY", state["search_tasks"])
        self.assertNotIn("ST-LEGACY", state["search_queue"])

    def test_missing_capabilities_fail_closed_instead_of_using_legacy_queries(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping({}))
            state = _inventory_state()
            state.update({
                "es_indices": ["mixed-events"],
                "es_fields": ["@timestamp", "process.name", "process.pid"],
                "es_fields_by_class": {},
                "es_indices_by_class": {},
                "es_field_capabilities": {},
                "es_field_capabilities_by_class": {},
                "timestamp_field": "@timestamp",
                "search_tasks": {},
                "search_queue": [],
            })
            engine._register_discovery_tasks(state)

        unsafe_origins = {"behavior_catalog", "trusted_indicator"}
        self.assertFalse(any(
            task.get("origin") in unsafe_origins
            for task in state["search_tasks"].values()
        ))
        self.assertTrue(
            state["coverage"]["behavior_catalog"]["unsupported_analytics"]
        )

    def test_mixed_mapping_is_available_to_both_host_and_network_families(self):
        from romulus.investigation.workflow import _field_names_by_class, _index_names_by_class

        mapping = {
            "mixed-events": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "host": {"properties": {"name": {"type": "keyword"}}},
                        "process": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "command_line": {"type": "wildcard"},
                            }
                        },
                        "source": {"properties": {"ip": {"type": "ip"}}},
                        "destination": {"properties": {"ip": {"type": "ip"}}},
                        "network": {"properties": {"protocol": {"type": "keyword"}}},
                        "dns": {
                            "properties": {
                                "question": {
                                    "properties": {"name": {"type": "keyword"}}
                                }
                            }
                        },
                    }
                }
            }
        }

        fields = _field_names_by_class(mapping)
        indices = _index_names_by_class(mapping)

        self.assertEqual(indices["host"], ["mixed-events"])
        self.assertEqual(indices["network"], ["mixed-events"])
        self.assertIn("@timestamp", fields["host"])
        self.assertIn("@timestamp", fields["network"])
        self.assertIn("process.name", fields["host"])
        self.assertIn("source.ip", fields["network"])

    def test_single_family_and_unclassified_mappings_keep_their_roles(self):
        from romulus.investigation.workflow import _index_names_by_class

        mapping = {
            "endpoint-events": {
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "process": {"properties": {"name": {"type": "keyword"}}},
                    "user": {"properties": {"name": {"type": "keyword"}}},
                }}
            },
            "flow-events": {
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "source": {"properties": {"ip": {"type": "ip"}}},
                    "destination": {"properties": {"ip": {"type": "ip"}}},
                }}
            },
            "misc-events": {
                "mappings": {"properties": {"message": {"type": "text"}}}
            },
        }

        indices = _index_names_by_class(mapping)

        self.assertEqual(indices["host"], ["endpoint-events"])
        self.assertEqual(indices["network"], ["flow-events"])
        self.assertEqual(indices["other"], ["misc-events"])

    def test_shared_firewall_metadata_does_not_claim_host_telemetry(self):
        from romulus.investigation.workflow import _index_names_by_class

        mapping = {
            "network-firewall": {
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "source": {"properties": {"ip": {"type": "ip"}}},
                    "destination": {"properties": {"ip": {"type": "ip"}}},
                    "user": {"properties": {"name": {"type": "keyword"}}},
                    "event": {"properties": {"code": {"type": "keyword"}}},
                }}
            }
        }

        indices = _index_names_by_class(mapping)

        self.assertNotIn("host", indices)
        self.assertEqual(indices["network"], ["network-firewall"])

    def test_authentication_mapping_with_source_context_remains_host_eligible(self):
        from romulus.investigation.workflow import _field_names_by_class, _index_names_by_class
        from romulus.intelligence.analytics import summarize_evidence

        properties = {
            "@timestamp": {"type": "date"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "event": {"properties": {
                "code": {"type": "keyword"},
                "category": {"type": "keyword"},
            }},
            "source": {"properties": {"ip": {"type": "ip"}}},
        }
        mapping = _mapping(properties)

        indices = _index_names_by_class(mapping)
        fields = _field_names_by_class(mapping)

        self.assertEqual(indices["host"], ["mixed-events"])
        self.assertEqual(indices["network"], ["mixed-events"])
        self.assertIn("@timestamp", fields["host"])
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), mapping)
            state = engine._collect_host(_inventory_state())
            state.update({"host": [], "network": [], "evidence_keys": []})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "authentication-1",
                "@timestamp": "2026-02-01T00:12:00Z",
                "event": {"category": "authentication", "code": "4624"},
                "host": {"name": "endpoint-01"},
                "user": {"name": "analyst"},
                "source": {"ip": "192.0.2.10"},
            }, {"match_all": {}})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "authentication-2",
                "@timestamp": "2026-02-01T00:13:00Z",
                "event": {"module": "system", "dataset": "system.auth"},
                "host": {"name": "linux-01"},
                "user": {"name": "analyst"},
                "source": {"ip": "192.0.2.11"},
                "message": "Accepted password for analyst",
            }, {"match_all": {}})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "host-event-code-1",
                "@timestamp": "2026-02-01T00:14:00Z",
                "event": {"code": "7045"},
                "host": {"name": "windows-01"},
                "source": {"ip": "192.0.2.12"},
                "message": "Service installation event",
            }, {"match_all": {}})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "network-firewall-1",
                "@timestamp": "2026-02-01T00:15:00Z",
                "event": {"category": "network", "code": "deny"},
                "host": {"name": "firewall-01"},
                "source": {"ip": "192.0.2.13"},
            }, {"match_all": {}})
            summary = summarize_evidence(state["host"], state["network"])

        self.assertEqual(len(state["host"]), 3)
        self.assertEqual(len(state["network"]), 1)
        self.assertEqual(summary["scope"]["host_events"], 3)
        self.assertEqual(summary["scope"]["network_events"], 1)

    def test_network_name_hint_blocks_context_only_host_classification(self):
        from romulus.investigation.workflow import _index_names_by_class

        mapping = {
            "network-tls": {
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "tls": {"properties": {
                        "client": {"properties": {"server_name": {"type": "keyword"}}}
                    }},
                    "user": {"properties": {"name": {"type": "keyword"}}},
                }}
            }
        }

        indices = _index_names_by_class(mapping)

        self.assertNotIn("host", indices)
        self.assertEqual(indices["network"], ["network-tls"])

    def test_host_name_only_mapping_remains_host_telemetry_without_network_markers(self):
        from romulus.investigation.workflow import _index_names_by_class

        mapping = {
            "endpoint-inventory": {
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "host": {"properties": {"name": {"type": "keyword"}}},
                }}
            }
        }

        indices = _index_names_by_class(mapping)

        self.assertEqual(indices["host"], ["endpoint-inventory"])
        self.assertNotIn("network", indices)

    def test_mixed_inventory_enables_timestamped_host_and_network_discovery(self):
        properties = {
            "@timestamp": {"type": "date"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {
                "name": {"type": "keyword"},
                "executable": {"type": "keyword"},
            }},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping(properties))
            state = engine._collect_host(_inventory_state())
            engine._register_discovery_tasks(state)

        families = {task["source_family"] for task in state["search_tasks"].values()}
        self.assertTrue(state["source_health"]["host"])
        self.assertEqual(state["timestamp_field"], "@timestamp")
        self.assertEqual(state["es_indices_by_class"]["host"], ["mixed-events"])
        self.assertEqual(state["es_indices_by_class"]["network"], ["mixed-events"])
        self.assertIn("host", families)
        self.assertIn("network", families)

    def test_mixed_index_routes_each_document_to_one_semantic_family(self):
        from romulus.intelligence.analytics import summarize_evidence

        properties = {
            "@timestamp": {"type": "date"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}}},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping(properties))
            state = engine._collect_host(_inventory_state())
            state.update({"host": [], "network": [], "evidence_keys": []})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "endpoint-1",
                "@timestamp": "2026-02-01T00:10:00Z",
                "event": {"category": "process"},
                "host": {"name": "endpoint-01"},
                "process": {"name": "cmd.exe"},
            }, {"match_all": {}})
            engine._add_es_hit(state, {
                "_index": "mixed-events",
                "_id": "network-1",
                "@timestamp": "2026-02-01T00:11:00Z",
                "event": {"category": "network", "module": "suricata"},
                "source": {"ip": "192.0.2.10"},
                "destination": {"ip": "198.51.100.20"},
            }, {"match_all": {}})
            summary = summarize_evidence(state["host"], state["network"])

        self.assertEqual(len(state["host"]), 1)
        self.assertEqual(len(state["network"]), 1)
        self.assertEqual(summary["scope"]["host_events"], 1)
        self.assertEqual(summary["scope"]["network_events"], 1)
        self.assertEqual(summary["host_profile"]["top_processes"][0]["value"], "cmd.exe")
        self.assertEqual(summary["network_profile"]["top_sources"][0]["value"], "192.0.2.10")

    def test_explicit_window_keeps_host_unavailable_without_mapped_timestamp(self):
        properties = {
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}}},
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            engine = _engine(Path(directory), _mapping(properties))
            state = engine._collect_host(_inventory_state())

        self.assertFalse(state["source_health"]["host"])
        self.assertNotIn("timestamp_field", state)
        self.assertIn("no usable mapped fields or timestamp", state["coverage"]["host"])


class CapturePathContractTests(unittest.TestCase):
    def test_runtime_accepts_canonical_and_safe_suffixed_capture_names(self):
        from romulus.tools.tshark_client import TSharkAdapter

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            names = ("capture.pcap", "capture.pcapng", "capture.pcap.1642993260",
                     "capture.pcapng.1642993260")
            paths = []
            for name in names:
                path = root / name
                path.write_bytes(b"synthetic capture placeholder")
                paths.append(path)
            adapter = TSharkAdapter(replace(Settings.from_env(), pcap_allowed_dirs=(root,)))

            approved = [adapter._approved(path) for path in paths]

            self.assertEqual(approved, [path.resolve() for path in paths])

    def test_runtime_rejects_arbitrary_extensions_and_outside_allowlist(self):
        from romulus.tools.tshark_client import TSharkAdapter

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            arbitrary = allowed / "capture.txt"
            disguised = allowed / "capture.pcap.exe"
            escaped = outside / "capture.pcap.1642993260"
            arbitrary.write_bytes(b"not a capture")
            disguised.write_bytes(b"not a capture")
            escaped.write_bytes(b"synthetic capture placeholder")
            adapter = TSharkAdapter(replace(Settings.from_env(), pcap_allowed_dirs=(allowed,)))

            with self.assertRaises(ValueError):
                adapter._approved(arbitrary)
            with self.assertRaises(ValueError):
                adapter._approved(disguised)
            with self.assertRaises(ValueError):
                adapter._approved(escaped)

    def test_doctor_and_runtime_accept_the_same_generated_capture(self):
        from romulus.cli import _configured_pcap_ready
        from romulus.tools.tshark_client import TSharkAdapter

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            capture = root / "capture.pcap.1642993260"
            capture.write_bytes(b"synthetic capture placeholder")
            settings = replace(
                Settings.from_env(),
                home=root,
                data_dir=root / "data",
                logs_dir=root / "logs",
                reports_dir=root / "reports",
                pcap_allowed_dirs=(root,),
                pcap_files=(capture,),
                arkime_username="",
                arkime_password="",
            )
            runtime_path = TSharkAdapter(settings)._approved(capture)
            doctor_ready = _configured_pcap_ready(capture, settings.pcap_allowed_dirs)

        self.assertEqual(runtime_path, capture.resolve())
        self.assertTrue(doctor_ready)


if __name__ == "__main__":
    unittest.main()
