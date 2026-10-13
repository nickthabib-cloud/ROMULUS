import json
import io
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

from romulus.config import Settings
from romulus.store import Store


class RetentionTests(unittest.TestCase):
    def test_compact_retention_keeps_reasoning_summary_and_removes_reasoning_payloads(self):
        from romulus.retention import _compact_state

        summary = {"investigator_calls": 2, "critic_calls": 2,
            "proposed_searches": 3, "admitted_searches": 1, "rejected_searches": 2,
            "last_gap": "critic_unavailable"}
        state = self._state([])
        state["coverage"]["reasoning_summary"] = summary
        state["reasoning_history"] = [{"grounded_reasoning": {
            "case_file": "CASE-FILE-PAYLOAD", "investigator": "INVESTIGATOR-PAYLOAD",
            "critic": "CRITIC-PAYLOAD"}}]

        compacted = _compact_state(state, {"EV-KEEP"})

        self.assertEqual(compacted["coverage"]["reasoning_summary"], summary)
        self.assertNotIn("reasoning_history", compacted)
        serialized = json.dumps(compacted, sort_keys=True)
        for payload in ("CASE-FILE-PAYLOAD", "INVESTIGATOR-PAYLOAD", "CRITIC-PAYLOAD"):
            self.assertNotIn(payload, serialized)

    def test_legacy_state_without_reasoning_summary_compacts_to_zero_free_absence(self):
        from romulus.retention import _compact_state

        state = self._state([])
        state["coverage"].pop("reasoning_summary", None)

        compacted = _compact_state(state, {"EV-KEEP"})

        self.assertNotIn("reasoning_summary", compacted["coverage"])

    def test_compact_scheduler_summary_does_not_resolve_short_result(self):
        from romulus.retention import _scheduler_summary

        state = {
            "search_tasks": {"ST-SHORT": {"task_id": "ST-SHORT", "source": "arkime",
                "origin": "candidate_follow_up", "status": "completed"}},
            "search_outcomes": [{"task_id": "ST-SHORT", "status": "completed",
                "matched_total": 2, "returned_total": 1, "capped": False,
                "timed_out": False, "shard_failures": 0, "incomplete": False}],
            "scheduler_history": [],
            "coverage": {},
        }

        self.assertEqual(_scheduler_summary(state)["unresolved_task_count"], 1)

    def _reports(self, root: Path, hunt_id: str):
        from docx import Document

        reports = root / "reports"
        reports.mkdir(exist_ok=True)
        text_path = reports / f"{hunt_id}-report.txt"
        text_path.write_text(f"ROMULUS completed technical report\nInvestigation: {hunt_id}\n", encoding="utf-8")
        docx_path = reports / f"{hunt_id}-report.docx"
        document = Document()
        document.add_paragraph(f"Investigation: {hunt_id}")
        document.save(docx_path)
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
            "progress_baseline": {"evidence_ids": ["EV-KEEP"], "changed_ids": ["working data"]},
            "progress_history": [
                {"stage": "analysis", "material_progress": True,
                    "signals": {"new_evidence": 1}, "stagnant_cycles": 0},
                {"stage": "reasoning", "material_progress": False,
                    "signals": {}, "stagnant_cycles": 1},
                {"stage": "analysis", "material_progress": False,
                    "signals": {}, "stagnant_cycles": 2},
            ],
            "stagnant_cycles": 2,
            "search_artifacts": [{"large": "working data"}],
            "search_tasks": {
                "ST-DONE": {"task_id": "ST-DONE", "source": "elasticsearch", "source_family": "host",
                    "origins": ["behavior_catalog", "candidate_follow_up"], "status": "completed"},
                "ST-OPEN": {"task_id": "ST-OPEN", "source": "arkime", "source_family": "network",
                    "origins": ["coverage_frontier"], "status": "queued"},
            },
            "search_queue": ["ST-OPEN"],
            "search_outcomes": [{"task_id": "ST-DONE", "status": "completed", "matched_total": 0,
                "returned_total": 0, "capped": False, "timed_out": False, "shard_failures": 0,
                "incomplete": False, "sampling": {"version": 1, "strategy": "time_stratified",
                    "requested_strata": 8, "covered_strata": 6,
                    "retained_by_stratum": [2, 2, 2, 2, 2, 2], "fallback_reason": "sparse_strata"}}],
            "scheduler_history": [{"event": "task_merged", "task_id": "ST-DONE"},
                {"event": "discovery_budget_gap", "unserved_families": ["network"]}],
            "coverage": {
                "time_scope": "all retained indexed time", "host": "available",
                "network": "available", "tool_calls_used": 8, "tool_call_limit": 20,
                "max_stagnant_cycles": 3, "stagnant_cycles": 2,
                "progress_summary": {"cycles_recorded": 3, "productive_cycles": 1,
                    "stagnant_cycles_recorded": 2, "current_stagnant_cycles": 2,
                    "max_stagnant_cycles_seen": 2, "signal_totals": {"new_evidence": 1},
                    "last_stage": "analysis", "last_material_signals": {},
                    "final_stop_basis": "lead_queue_exhausted"},
                "analytic_summary": {"large": ["working data"]},
                "scheduler_gaps": [{"phase": "investigation", "reason": "tool_call_budget",
                    "queued_task_ids": ["ST-OPEN"]}],
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
            self.assertNotIn("search_tasks", persisted)
            self.assertNotIn("search_queue", persisted)
            self.assertNotIn("search_outcomes", persisted)
            self.assertNotIn("scheduler_history", persisted)
            self.assertNotIn("progress_baseline", persisted)
            self.assertNotIn("progress_history", persisted)
            self.assertNotIn("progress_totals", persisted)
            self.assertNotIn("stagnant_cycles", persisted)
            self.assertEqual(persisted["coverage"]["max_stagnant_cycles"],3)
            self.assertEqual(persisted["coverage"]["stagnant_cycles"],2)
            self.assertEqual(persisted["coverage"]["progress_summary"],state["coverage"]["progress_summary"])
            self.assertEqual(persisted["coverage"]["progress_summary"]["final_stop_basis"],
                persisted["termination_reason"])
            scheduler=persisted["coverage"]["scheduler_summary"]
            self.assertEqual(scheduler["tasks_total"],2)
            self.assertEqual(scheduler["by_source"],{"arkime":1,"elasticsearch":1})
            self.assertEqual(scheduler["by_status"],{"completed":1,"queued":1})
            self.assertEqual(scheduler["duplicate_merges_avoided"],1)
            self.assertEqual(scheduler["unresolved_task_count"],1)
            self.assertTrue(scheduler["source_fairness_gaps"])
            sampling=persisted["coverage"]["sampling_summary"]
            self.assertEqual(sampling["tasks_with_sampling"],1)
            self.assertEqual(sampling["by_strategy"],{"time_stratified":1})
            self.assertEqual(sampling["requested_strata"],8)
            self.assertEqual(sampling["covered_strata"],6)
            self.assertEqual(sampling["retained_records"],12)
            self.assertEqual(sampling["fallbacks"],{"sparse_strata":1})
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

    def test_malformed_or_wrong_hunt_reports_never_authorize_compaction(self):
        from romulus.retention import RetentionError, apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            reports = root / "reports"
            reports.mkdir()
            text_path = reports / "HUNT-ONE-report.txt"
            text_path.write_text("Investigation: HUNT-ONE\n", encoding="utf-8")
            docx_path = reports / "HUNT-ONE-report.docx"
            with zipfile.ZipFile(docx_path, "w") as package:
                package.writestr("[Content_Types].xml", "<Types />")
                package.writestr("word/document.xml", "<document />")
            store = Store(root / "data", root / "logs")
            state = self._state([str(docx_path), str(text_path)])
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"preserve": True}})

            with self.assertRaises(RetentionError):
                apply_retention(store, state, policy="compact", automatic=True)

            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)

            wrong_paths = self._reports(root, "HUNT-ONE-OTHER")
            state["report_paths"] = wrong_paths
            with self.assertRaises(RetentionError):
                apply_retention(store, state, policy="compact", automatic=True)
            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)

    def test_jsonl_rewrite_serializes_concurrent_unrelated_append(self):
        import romulus.store as store_module

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            store.audit({"hunt_id": "HUNT-ONE", "result_count": 1})
            entered = threading.Event()
            release = threading.Event()
            append_done = threading.Event()
            failures = []
            original_filter = store_module._filter_jsonl

            def slow_filter(path, key, value):
                if path == store.audit_path:
                    entered.set()
                    if not release.wait(2):
                        raise TimeoutError("test did not release JSONL rewrite")
                return original_filter(path, key, value)

            def rewrite():
                try: store.remove_hunt_log_records("HUNT-ONE")
                except Exception as exc: failures.append(exc)

            def append():
                try: store.audit({"hunt_id": "HUNT-TWO", "result_count": 2})
                except Exception as exc: failures.append(exc)
                finally: append_done.set()

            with patch("romulus.store._filter_jsonl", side_effect=slow_filter):
                rewrite_thread = threading.Thread(target=rewrite)
                rewrite_thread.start()
                self.assertTrue(entered.wait(2))
                append_thread = threading.Thread(target=append)
                append_thread.start()
                self.assertFalse(append_done.wait(0.1))
                release.set()
                rewrite_thread.join(2)
                append_thread.join(2)

            self.assertFalse(failures)
            self.assertEqual(store.audit_records("HUNT-ONE"), [])
            self.assertEqual(store.audit_records("HUNT-TWO")[0]["result_count"], 2)

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

            compacted = apply_retention(store, state, policy="compact", automatic=False, finalize=True)

            self.assertEqual(compacted["status"], "partial")
            self.assertEqual(compacted["retention"]["status"], "completed")
            self.assertEqual([item["evidence_id"] for item in store.list_evidence("HUNT-ONE")], ["EV-KEEP"])

    def test_full_policy_preserves_working_data(self):
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state(self._reports(root, "HUNT-ONE"))
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

    def test_finalize_cli_full_policy_reports_truthfully_and_preserves_data(self):
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
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"preserve": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["finalize", "--id", "HUNT-ONE", "--retention", "full"])

            finalized = store.load_state("HUNT-ONE")
            text_report = next(Path(path) for path in finalized["report_paths"] if path.endswith(".txt"))
            self.assertEqual(result, 0)
            self.assertEqual(finalized["retention_policy"], "full")
            self.assertEqual(finalized["retention"]["policy"], "full")
            self.assertTrue(finalized["retention"]["finalized"])
            self.assertEqual(store.evidence_count("HUNT-ONE"), 2)
            self.assertIn("complete raw evidence remains in SQLite", text_report.read_text(encoding="utf-8"))
            self.assertNotIn("uncited raw evidence are removed", text_report.read_text(encoding="utf-8"))

    def test_legacy_compacted_partial_hunt_is_not_resumed(self):
        from romulus.investigation.workflow import HuntEngine

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            # f2008b1 persisted compact completion without a separate finalized flag.
            state["retention"] = {"policy": "compact", "status": "completed"}
            store.save_state("HUNT-ONE", state)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            engine.run = lambda *args, **kwargs: self.fail("A finalized hunt must not resume")

            resumed = engine.resume("HUNT-ONE")

            self.assertEqual(resumed["retention"]["status"], "completed")

    def test_full_retained_hunt_can_be_truthfully_recompacted(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="full",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state([], status="partial")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"drop": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                self.assertEqual(main(["finalize", "--id", "HUNT-ONE", "--retention", "full"]), 0)
                self.assertEqual(main(["compact", "--id", "HUNT-ONE"]), 0)

            compacted = store.load_state("HUNT-ONE")
            text_report = next(Path(path) for path in compacted["report_paths"] if path.endswith(".txt"))
            self.assertEqual(compacted["retention_policy"], "compact")
            self.assertEqual(compacted["retention"]["policy"], "compact")
            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertIn("uncited raw evidence are scheduled for removal", text_report.read_text(encoding="utf-8"))
            self.assertIn("This finalized investigation uses compact retention", text_report.read_text(encoding="utf-8"))
            self.assertNotIn("complete raw evidence remains in SQLite", text_report.read_text(encoding="utf-8"))

    def test_cli_rejects_compact_to_full_before_changing_reports_or_state(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="compact",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            state["retention_policy"] = "compact"
            state["retention"] = {"policy": "compact", "status": "completed", "finalized": True}
            store.save_state("HUNT-ONE", state)
            before_state = store.load_state("HUNT-ONE")
            before_files = {path.name: path.read_bytes() for path in settings.reports_dir.iterdir()}

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["finalize", "--id", "HUNT-ONE", "--retention", "full"])

            self.assertEqual(result, 1)
            self.assertEqual(store.load_state("HUNT-ONE"), before_state)
            self.assertEqual({path.name: path.read_bytes() for path in settings.reports_dir.iterdir()}, before_files)

    def test_compact_cli_recognizes_legacy_finalized_partial_hunt(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="compact",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            state["retention_policy"] = "compact"
            state["retention"] = {"policy": "compact", "status": "completed"}
            store.save_state("HUNT-ONE", state)

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["compact", "--id", "HUNT-ONE"])

            self.assertEqual(result, 0)
            self.assertTrue(store.load_state("HUNT-ONE")["retention"]["finalized"])

    def test_incomplete_compaction_report_describes_policy_intent_not_completed_cleanup(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="full",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state([], status="partial")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-KEEP", "raw": {"keep": True}})
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"drop": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                self.assertEqual(main(["finalize", "--id", "HUNT-ONE", "--retention", "full"]), 0)
                with patch("romulus.store.Store.remove_hunt_log_records", side_effect=OSError("locked")):
                    self.assertEqual(main(["compact", "--id", "HUNT-ONE"]), 1)

            failed = store.load_state("HUNT-ONE")
            text_report = next(Path(path) for path in failed["report_paths"] if path.endswith(".txt"))
            report_text = text_report.read_text(encoding="utf-8")
            self.assertEqual(failed["retention"]["status"], "incomplete")
            self.assertIn("scheduled for removal", report_text)
            self.assertNotIn("working audit records and uncited raw evidence are removed", report_text)

    def test_running_hunt_cannot_be_finalized_or_compacted(self):
        from romulus.retention import RetentionError, apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state(self._reports(root, "HUNT-ONE"), status="running")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"preserve": True}})

            with self.assertRaises(RetentionError):
                apply_retention(store, state, policy="compact", automatic=False, finalize=True)

            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertEqual(store.load_state("HUNT-ONE")["status"], "running")

    def test_completed_compaction_cannot_be_relabelled_full(self):
        from romulus.retention import RetentionError, apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = self._state(self._reports(root, "HUNT-ONE"))
            store.save_state("HUNT-ONE", state)
            compacted = apply_retention(store, state, policy="compact", automatic=True)

            with self.assertRaises(RetentionError):
                apply_retention(store, compacted, policy="full", automatic=False)

            self.assertEqual(store.load_state("HUNT-ONE")["retention"]["policy"], "compact")

    def test_full_finalized_partial_hunt_is_not_resumed(self):
        from romulus.investigation.workflow import HuntEngine
        from romulus.retention import apply_retention

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs", retention_policy="full",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state(self._reports(root, "HUNT-ONE"), status="partial")
            store.save_state("HUNT-ONE", state)
            finalized = apply_retention(store, state, policy="full", automatic=False, finalize=True)
            engine = HuntEngine(settings, store, offline=True, use_ollama=False)
            engine.run = lambda *args, **kwargs: self.fail("A full-policy finalized hunt must not resume")

            resumed = engine.resume("HUNT-ONE")

            self.assertTrue(finalized["retention"]["finalized"])
            self.assertEqual(resumed["retention"]["status"], "retained")

    def test_finalize_cli_rejects_running_hunt_before_report_generation(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            state = self._state([], status="running")
            store.save_state("HUNT-ONE", state)
            store.add_evidence("HUNT-ONE", {"evidence_id": "EV-DROP", "raw": {"preserve": True}})

            with patch("romulus.cli.Settings.from_env", return_value=settings):
                result = main(["finalize", "--id", "HUNT-ONE"])

            self.assertEqual(result, 1)
            self.assertEqual(store.evidence_count("HUNT-ONE"), 1)
            self.assertEqual(store.load_state("HUNT-ONE").get("report_paths"), [])

    def test_cli_surfaces_completed_hunt_retention_failure(self):
        from romulus.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(), home=root, reports_dir=root / "reports",
                data_dir=root / "data", logs_dir=root / "logs",
            )
            class Engine:
                def __init__(self, *args, **kwargs): pass
                def run(self, objective):
                    return {
                        "hunt_id": "HUNT-WARN", "status": "completed", "outcome": "insufficient_evidence",
                        "summary": "Completed hunt.", "termination_reason": "lead_queue_exhausted",
                        "tool_calls": 1, "depth": 1, "report_paths": [],
                        "retention": {"policy": "compact", "status": "incomplete", "error_type": "OSError"},
                    }
            output = io.StringIO()
            with patch("romulus.cli.Settings.from_env", return_value=settings), patch("romulus.cli.HuntEngine", Engine), redirect_stdout(output):
                result = main(["hunt", "--objective", "Hunt for suspicious activity"])

            self.assertEqual(result, 3)
            self.assertIn("RETENTION WARNING", output.getvalue())


if __name__ == "__main__":
    unittest.main()
