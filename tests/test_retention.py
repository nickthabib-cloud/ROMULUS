import json
import sqlite3
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from romulus.config import Settings
from romulus.store import Store


class RetentionTests(unittest.TestCase):
    def _reports(self, root: Path, hunt_id: str):
        reports = root / "reports"
        reports.mkdir()
        text_path = reports / f"{hunt_id}-report.txt"
        text_path.write_text("ROMULUS completed technical report", encoding="utf-8")
        docx_path = reports / f"{hunt_id}-report.docx"
        with zipfile.ZipFile(docx_path, "w") as package:
            package.writestr("[Content_Types].xml", "<Types />")
            package.writestr("word/document.xml", "<document />")
        return [str(docx_path), str(text_path)]

    def _state(self, report_paths, status="completed"):
        return {
            "hunt_id": "HUNT-ONE",
            "objective": "Hunt for suspicious lateral movement",
            "status": status,
            "outcome": "evidence_supported_lead",
            "termination_reason": "lead_queue_exhausted",
            "started_at": "2026-10-10T00:00:00Z",
            "finished_at": "2026-10-10T00:10:00Z",
            "duration_ms": 600000,
            "summary": "One cited lead requires review.",
            "report_paths": report_paths,
            "findings": [{
                "finding_id": "F-ONE", "title": "Cited lead", "status": "suspected",
                "evidence_ids": ["EV-KEEP"], "attack_path_ids": ["PATH-ONE"],
            }],
            "candidate_leads": [{
                "candidate_id": "CL-ONE", "title": "Cited lead", "customer_visible": True,
                "evidence_ids": ["EV-KEEP"], "disposition": "corroborated",
            }, {
                "candidate_id": "CL-INTERNAL", "title": "Working lead", "customer_visible": False,
                "evidence_ids": ["EV-DROP"], "disposition": "unresolved",
            }],
            "host": [{"evidence_id": "EV-KEEP"}, {"evidence_id": "EV-DROP"}],
            "network": [],
            "queries": [{"large": "working data"}],
            "tool_runs": [{"large": "working data"}],
            "reasoning_history": [{"large": "working data"}],
            "search_artifacts": [{"large": "working data"}],
            "coverage": {
                "time_scope": "all retained indexed time", "host": "available",
                "network": "available", "tool_calls_used": 8, "tool_call_limit": 20,
                "analytic_summary": {"large": ["working data"]},
            },
            "investigation_graph": {
                "version": 1,
                "summary": {"activity_nodes": 2},
                "nodes": [
                    {"node_id": "evidence:EV-KEEP", "node_type": "evidence", "evidence_id": "EV-KEEP"},
                    {"node_id": "activity:EV-KEEP", "node_type": "activity", "evidence_ids": ["EV-KEEP"]},
                    {"node_id": "evidence:EV-DROP", "node_type": "evidence", "evidence_id": "EV-DROP"},
                    {"node_id": "activity:EV-DROP", "node_type": "activity", "evidence_ids": ["EV-DROP"]},
                ],
                "edges": [
                    {"edge_id": "E-KEEP", "source": "evidence:EV-KEEP", "target": "activity:EV-KEEP", "evidence_ids": ["EV-KEEP"]},
                    {"edge_id": "E-DROP", "source": "evidence:EV-DROP", "target": "activity:EV-DROP", "evidence_ids": ["EV-DROP"]},
                ],
                "paths": [{
                    "path_id": "PATH-ONE", "finding_id": "F-ONE",
                    "steps": [{"evidence_ids": ["EV-KEEP"], "activity_node_id": "activity:EV-KEEP"}],
                    "relationships": [], "caveats": [], "gaps": [],
                }],
            },
        }

    def _checkpoint_rows(self, store: Store):
        db=sqlite3.connect(store.checkpoint_path)
        try:
            db.executescript("""
                CREATE TABLE checkpoints(thread_id TEXT, checkpoint_ns TEXT, checkpoint_id TEXT);
                CREATE TABLE writes(thread_id TEXT, checkpoint_ns TEXT, checkpoint_id TEXT);
            """)
            for hunt_id in ("HUNT-ONE", "HUNT-TWO"):
                db.execute("INSERT INTO checkpoints VALUES(?,?,?)", (hunt_id, "", "CP-1"))
                db.execute("INSERT INTO writes VALUES(?,?,?)", (hunt_id, "", "CP-1"))
            db.commit()
        finally:
            db.close()

    def test_compact_retention_is_hunt_scoped_report_gated_and_idempotent(self):
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state(self._reports(root, "HUNT-ONE"))
            store.save_state("HUNT-ONE", state)
            store.save_state("HUNT-TWO", {"hunt_id": "HUNT-TWO", "status": "partial"})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"large": "discard"}})
            store.add_evidence("HUNT-TWO", {"evidence_id": "EV-OTHER", "raw": {"other": True}})
            store.audit({"hunt_id": "HUNT-ONE", "result_count": 1})
            store.audit({"hunt_id": "HUNT-TWO", "result_count": 1})
            store.upsert_finding("HUNT-ONE", {"finding_id": "F-ONE", "evidence_ids": ["EV-KEEP"]})
            store.upsert_finding("HUNT-TWO", {"finding_id": "F-TWO", "evidence_ids": ["EV-OTHER"]})
            self._checkpoint_rows(store)

            compacted = apply_retention(store, state, policy="compact", automatic=True)
            second = apply_retention(store, compacted, policy="compact", automatic=True)

            self.assertEqual(compacted["retention"]["status"], "completed")
            self.assertEqual(second["retention"]["status"], "completed")
            self.assertEqual([item["evidence_id"] for item in store.list_evidence("HUNT-ONE")], ["EV-KEEP"])
            self.assertEqual([item["evidence_id"] for item in store.list_evidence("HUNT-TWO")], ["EV-OTHER"])
            persisted = store.load_state("HUNT-ONE")
            self.assertNotIn("host", persisted)
            self.assertNotIn("tool_runs", persisted)
            self.assertEqual(len(persisted["candidate_leads"]), 1)
            self.assertFalse(any(node.get("evidence_id") == "EV-DROP" for node in persisted["investigation_graph"]["nodes"]))
            self.assertTrue(all(Path(path).exists() for path in persisted["report_paths"]))
            self.assertEqual(store.audit_records("HUNT-ONE"), [])
            self.assertEqual(len(store.audit_records("HUNT-TWO")), 1)
            event_rows = [json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["investigation_id"] for row in event_rows], ["HUNT-TWO"])
            db=sqlite3.connect(store.checkpoint_path)
            try:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM checkpoints WHERE thread_id='HUNT-ONE'").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM checkpoints WHERE thread_id='HUNT-TWO'").fetchone()[0], 1)
            finally:
                db.close()

    def test_invalid_reports_prevent_any_compaction(self):
        from romulus.retention import RetentionError, apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state([str(root / "missing.docx"), str(root / "missing.txt")])
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"large": "preserve"}})

            with self.assertRaises(RetentionError):
                apply_retention(store, state, policy="compact", automatic=True)

            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertIn("host", store.load_state("HUNT-ONE"))

    def test_partial_hunt_remains_resumable_during_automatic_retention(self):
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state([], status="partial")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"large": "preserve"}})

            retained = apply_retention(store, state, policy="compact", automatic=True)

            self.assertEqual(retained["retention"]["status"], "resumable")
            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertIn("host", store.load_state("HUNT-ONE"))

    def test_explicit_finalization_can_compact_a_reported_partial_hunt(self):
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"large": "discard"}})

            compacted = apply_retention(store, state, policy="compact", automatic=False)

            self.assertEqual(compacted["status"], "partial")
            self.assertEqual(compacted["retention"]["status"], "completed")
            self.assertEqual([item["evidence_id"] for item in store.list_evidence("HUNT-ONE")], ["EV-KEEP"])

    def test_full_policy_preserves_working_data(self):
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state([])
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"large": "preserve"}})

            retained = apply_retention(store, state, policy="full", automatic=True)

            self.assertEqual(retained["retention"]["status"], "retained")
            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertIn("host", store.load_state("HUNT-ONE"))

    def test_engine_auto_compacts_only_after_graph_connection_closes(self):
        from romulus.investigation.workflow import HuntEngine

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="compact",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            reports = self._reports(root, "HUNT-AUTO")

            class Connection:
                closed = False
                def close(self): self.closed = True

            connection = Connection()
            outer = self
            class App:
                def invoke(self, state, config):
                    result = outer._state(reports)
                    result["hunt_id"] = "HUNT-AUTO"
                    result["started_epoch"] = state["started_epoch"]
                    store.add_evidence("HUNT-AUTO", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
                    store.add_evidence("HUNT-AUTO", {"evidence_id": "EV-DROP", "raw": {"drop": True}})
                    return result

            engine._graph = lambda: (App(), connection)
            original_compact = store.compact_investigation
            def checked_compact(hunt_id, state, retain_evidence_ids):
                outer.assertTrue(connection.closed)
                return original_compact(hunt_id, state, retain_evidence_ids)
            store.compact_investigation = checked_compact

            result = engine.run("Hunt for SMB lateral movement", hunt_id="HUNT-AUTO")

            self.assertEqual(result["retention"]["status"], "completed")
            self.assertNotIn("host", result)
            self.assertEqual([item["evidence_id"] for item in store.list_evidence("HUNT-AUTO")], ["EV-KEEP"])

    def test_compact_cli_applies_policy_to_an_existing_completed_hunt(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="compact",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"))
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"drop": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["compact", "--id", "HUNT-ONE"])

            self.assertEqual(result, 0)
            self.assertEqual(store.load_state("HUNT-ONE")["retention"]["status"], "completed")

    def test_finalize_cli_reports_and_compacts_a_partial_hunt(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("Install python-docx for explicit finalization verification")
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="compact",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state([], status="partial")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"drop": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["finalize", "--id", "HUNT-ONE"])

            finalized = store.load_state("HUNT-ONE")
            self.assertEqual(result, 0)
            self.assertEqual(finalized["status"], "partial")
            self.assertEqual(finalized["retention"]["status"], "completed")
            self.assertTrue(all(Path(path).exists() for path in finalized["report_paths"]))

    def test_explicitly_finalized_partial_hunt_is_not_resumed(self):
        from romulus.investigation.workflow import HuntEngine

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            state["retention"] = {"policy": "compact", "status": "completed"}
            store.save_state("HUNT-ONE", state)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            engine.run = lambda *args, **kwargs: self.fail("A finalized hunt must not resume")

            resumed = engine.resume("HUNT-ONE")

            self.assertEqual(resumed["retention"]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
