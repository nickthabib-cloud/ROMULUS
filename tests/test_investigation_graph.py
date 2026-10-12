import unittest
import tempfile
from dataclasses import replace
from pathlib import Path


class InvestigationGraphTests(unittest.TestCase):
    def _events(self):
        return [
            {
                "evidence_id": "EV-NET-1",
                "source": "arkime",
                "observed_at": "2026-10-10T14:02:58Z",
                "observation": "SMB connection from 10.20.0.15 to 10.20.0.22",
                "asset": "10.20.0.22",
                "raw": {
                    "src_ip": "10.20.0.15",
                    "dst_ip": "10.20.0.22",
                    "dst_port": 445,
                    "protocol": "smb",
                    "session_id": "session-7",
                },
            },
            {
                "evidence_id": "EV-HOST-1",
                "source": "elasticsearch",
                "observed_at": "2026-10-10T14:03:12+00:00",
                "observation": "Successful network logon for LAB\\svc-backup",
                "asset": "LAB-WS02",
                "raw": {
                    "event_id": 4624,
                    "ip": "10.20.0.15",
                    "host": "LAB-WS02",
                    "account": "LAB\\svc-backup",
                },
            },
            {
                "evidence_id": "EV-HOST-2",
                "source": "elasticsearch",
                "observed_at": "2026-10-10T14:04:02Z",
                "observation": "Service installation on lab-ws02",
                "asset": "lab-ws02",
                "raw": {
                    "event_id": 7045,
                    "host": "lab-ws02",
                    "account": "LAB\\svc-backup",
                    "service": "LabUpdateSvc",
                },
            },
        ]

    def test_builds_deterministic_typed_graph_from_evidence(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph

        events = self._events()
        correlations = [
            {
                "host_ref": "EV-HOST-1",
                "network_ref": "EV-NET-1",
                "delta_seconds": 14,
                "score": 0.72,
                "reasons": ["shared typed IP: 10.20.0.15"],
                "caveat": "Validate identity and clock alignment.",
            }
        ]
        graph = build_investigation_graph(events, correlations)
        reversed_graph = build_investigation_graph(list(reversed(events)), list(reversed(correlations)))

        self.assertEqual(graph, reversed_graph)
        node_types = {node["node_type"] for node in graph["nodes"]}
        self.assertEqual(node_types, {"evidence", "activity", "entity"})
        activity_types = {
            node["activity_type"]
            for node in graph["nodes"]
            if node["node_type"] == "activity"
        }
        self.assertEqual(activity_types, {"network_connection", "authentication", "service_change"})

        host_entities = [
            node for node in graph["nodes"]
            if node["node_type"] == "entity" and node["entity_type"] == "host"
        ]
        self.assertEqual([node["normalized_value"] for node in host_entities], ["lab-ws02"])
        self.assertTrue(any(
            node.get("entity_type") == "ip" and node.get("normalized_value") == "10.20.0.15"
            for node in graph["nodes"]
        ))

        support_edges = [edge for edge in graph["edges"] if edge["relationship"] == "supports"]
        self.assertEqual(len(support_edges), 3)
        self.assertTrue(all(edge["basis"] == "observed" and len(edge["evidence_ids"]) == 1 for edge in support_edges))

    def test_cross_event_links_are_inferred_and_never_claim_causation(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph

        graph = build_investigation_graph(
            self._events(),
            [{
                "host_ref": "EV-HOST-1",
                "network_ref": "EV-NET-1",
                "delta_seconds": 14,
                "score": 0.72,
                "reasons": ["shared typed IP: 10.20.0.15"],
                "caveat": "Validate identity and clock alignment.",
            }],
        )
        cross_event = [
            edge for edge in graph["edges"]
            if edge["relationship"] in {"precedes_with_shared_entity", "possibly_related"}
        ]

        self.assertTrue(cross_event)
        self.assertTrue(any(edge["relationship"] == "possibly_related" for edge in cross_event))
        self.assertTrue(any(edge["relationship"] == "precedes_with_shared_entity" for edge in cross_event))
        for edge in cross_event:
            self.assertEqual(edge["basis"], "inferred")
            self.assertGreaterEqual(len(edge["evidence_ids"]), 2)
            self.assertIn("not causation", " ".join(edge.get("caveats", [])).lower())

    def test_nested_ecs_containers_never_become_entity_values(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph

        event = {
            "evidence_id": "EV-ECS", "source": "elasticsearch",
            "observed_at": "2026-10-10T12:00:00Z", "observation": "Nested ECS event",
            "raw": {
                "host": {"name": "WS-01", "ip": ["10.0.0.4"]},
                "user": {"name": "ALICE"},
                "service": {"name": "Updater"},
                "task": {"name": "DailyCheck"},
            },
        }

        graph = build_investigation_graph([event])
        entities = [node for node in graph["nodes"] if node["node_type"] == "entity"]
        values = {node["normalized_value"] for node in entities}

        self.assertTrue({"ws-01", "10.0.0.4", "alice", "updater", "dailycheck"} <= values)
        self.assertFalse(any("{" in value or "}" in value for value in values))

    def test_analysis_persists_graph_in_declared_hunt_state(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine, HuntState
        from romulus.store import Store

        self.assertIn("investigation_graph", HuntState.__annotations__)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs",
            )
            state = {
                "hunt_id": "HUNT-GRAPH", "objective": "Hunt for SMB lateral movement",
                "host": self._events()[1:], "network": self._events()[:1],
                "hypotheses": [], "findings": [], "candidate_leads": [],
                "coverage": {}, "lead_catalog": [], "completed_leads": [],
                "pivot_results": [], "es_indices": [], "stage_history": [],
            }
            analyzed = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=True)._analyze(state)

        self.assertEqual(analyzed["investigation_graph"]["summary"]["activity_nodes"], 3)
        self.assertTrue(analyzed["investigation_graph"]["edges"])
        self.assertTrue(analyzed["investigation_graph"]["paths"])
        self.assertEqual(
            analyzed["findings"][0]["attack_path_ids"],
            [path["path_id"] for path in analyzed["investigation_graph"]["paths"]],
        )

    def test_finding_paths_use_only_cited_evidence_and_keep_gaps(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph, derive_finding_paths

        events = self._events() + [{
            "evidence_id": "EV-UNRELATED",
            "source": "elasticsearch",
            "observed_at": "2026-10-10T16:00:00Z",
            "observation": "Unrelated file creation on LAB-WS99",
            "asset": "LAB-WS99",
            "raw": {"host": "LAB-WS99", "file": {"path": "/tmp/unrelated"}},
        }]
        graph = build_investigation_graph(events, [{
            "host_ref": "EV-HOST-1", "network_ref": "EV-NET-1",
            "delta_seconds": 14, "score": 0.72,
            "reasons": ["shared typed IP: 10.20.0.15"],
        }])
        findings = [{
            "finding_id": "F-1", "title": "Cited sequence",
            "evidence_ids": ["EV-HOST-1", "EV-NET-1", "EV-UNRELATED"],
        }]

        paths = derive_finding_paths(graph, findings)

        self.assertEqual(len(paths), 2)
        cited = {
            evidence_id
            for path in paths
            for step in path["steps"]
            for evidence_id in step["evidence_ids"]
        }
        self.assertEqual(cited, {"EV-HOST-1", "EV-NET-1", "EV-UNRELATED"})
        self.assertNotIn("EV-HOST-2", cited)
        connected = next(path for path in paths if len(path["steps"]) == 2)
        self.assertEqual(
            [step["evidence_ids"][0] for step in connected["steps"]],
            ["EV-NET-1", "EV-HOST-1"],
        )
        self.assertEqual(connected["relationships"][0]["relationship"], "possibly_related")
        self.assertTrue(all(path["gaps"] for path in paths))
        self.assertIn("disconnected", paths[0]["gaps"][0].lower())

    def test_analysis_attaches_stable_path_ids_to_findings(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph, derive_finding_paths

        graph = build_investigation_graph(self._events(), [{
            "host_ref": "EV-HOST-1", "network_ref": "EV-NET-1",
            "delta_seconds": 14, "score": 0.72,
            "reasons": ["shared typed IP: 10.20.0.15"],
        }])
        findings = [{
            "finding_id": "F-1", "title": "Cited sequence",
            "evidence_ids": ["EV-HOST-1", "EV-NET-1"],
        }]

        first = derive_finding_paths(graph, findings)
        second = derive_finding_paths(graph, list(reversed(findings)))

        self.assertEqual(first, second)
        self.assertEqual(first[0]["finding_id"], "F-1")
        self.assertTrue(first[0]["path_id"].startswith("PATH-"))

    def test_report_boundary_attaches_paths_to_late_findings(self):
        from romulus.intelligence.investigation_graph import build_investigation_graph
        from romulus.investigation.workflow import _attach_finding_paths

        state = {
            "findings": [{
                "finding_id": "F-LATE", "title": "Late cited finding",
                "evidence_ids": ["EV-HOST-1", "EV-NET-1"],
            }],
            "investigation_graph": build_investigation_graph(self._events(), [{
                "host_ref": "EV-HOST-1", "network_ref": "EV-NET-1",
                "delta_seconds": 14, "score": 0.72,
                "reasons": ["shared typed IP: 10.20.0.15"],
            }]),
        }

        _attach_finding_paths(state)

        self.assertTrue(state["findings"][0]["attack_path_ids"])
        self.assertEqual(
            state["findings"][0]["attack_path_ids"],
            [path["path_id"] for path in state["investigation_graph"]["paths"]],
        )


if __name__ == "__main__":
    unittest.main()
