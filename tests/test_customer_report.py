import tempfile
import unittest
from pathlib import Path


class CustomerWordReportTests(unittest.TestCase):
    def _state(self):
        return {
            "hunt_id": "HUNT-CUSTOMER",
            "status": "completed",
            "outcome": "evidence_supported_lead",
            "termination_reason": "lead_queue_exhausted",
            "objective": "Hunt for suspicious execution and lateral movement from 2026-10-10 to 2026-10-11.",
            "summary": "ROMULUS identified one suspicious execution chain that requires analyst validation.",
            "retention_policy": "compact",
            "duration_ms": 42000,
            "tool_calls": 7,
            "depth": 3,
            "coverage": {
                "time_scope": "2026-10-10T00:00:00Z through 2026-10-11T00:00:00Z",
                "host": "available; 123 events examined",
                "network": "available; 18 sessions examined",
                "tool_call_limit": 20,
                "sequence_analytics": {
                    "total": 89, "executable": 26, "reference_only": 63,
                    "matched": 1, "evaluated_events": 141, "event_limit_reached": False,
                    "by_rule": {
                        "CUR-SEQ-001": {"state": "matched"},
                        "CUR-SEQ-002": {"state": "partial"},
                        "CUR-SEQ-003": {"state": "reference_only"},
                    },
                },
                "aggregate_analytics": {
                    "total": 206, "executable": 18, "reference_only": 188,
                    "matched": 0, "evaluated_events": 141, "event_limit_reached": False,
                    "by_rule": {
                        "CUR-AGG-001": {"state": "no_match"},
                        "CUR-AGG-002": {"state": "reference_only"},
                    },
                },
                "baseline_analytics": {
                    "total": 58, "executable": 43, "reference_only": 15,
                    "matched": 0, "evaluated_events": 141, "event_limit_reached": False,
                    "by_rule": {
                        "CUR-BASE-001": {"state": "warming"},
                        "CUR-BASE-002": {"state": "reference_only"},
                    },
                },
                "scheduler_gaps": [{"phase":"report_finalization","reason":"tool_call_budget",
                    "budget_limited_task_count":3,
                    "budget_limited_task_ids":["ST-BUDGET-001","ST-BUDGET-002"]}],
            },
            "findings": [
                {
                    "finding_id": "F-001",
                    "title": "Suspicious PowerShell execution",
                    "status": "suspected",
                    "confidence": "moderate",
                    "observation": "PowerShell launched an encoded command from a temporary directory on WS-17.",
                    "interpretation": "The execution pattern is consistent with script-based payload execution and needs validation.",
                    "confidence_justification": "Host execution and matching network activity were observed in the same time window.",
                    "alternatives": ["An authorized administration script."],
                    "follow_up": ["Validate the command with the WS-17 owner.", "Review the destination IP for related activity."],
                    "evidence_ids": ["EV-RAW-001"],
                    "affected_assets": ["WS-17"],
                    "technique_id": "T1059.001",
                    "attack_path_ids": ["PATH-001"],
                }
            ],
            "hypotheses": [
                {
                    "title": "PowerShell execution",
                    "technique_id": "T1059.001",
                    "status": "supported",
                    "confidence": "moderate",
                    "rationale": "customer rationale",
                }
            ],
            "candidate_leads": [
                {
                    "candidate_id": "CL-HIGH",
                    "title": "Suspicious PowerShell execution",
                    "priority_score": 82,
                    "priority_tier": "high",
                    "disposition": "corroborated",
                    "customer_visible": True,
                    "kind": "behavior",
                    "evidence_ids": ["EV-RAW-001"],
                    "attack_techniques": ["T1059.001"],
                    "score_reasons": ["process and network corroboration"],
                    "benign_explanations": ["authorized administration"],
                    "follow_up": ["Validate with the asset owner."],
                },
                {
                    "candidate_id": "CL-LOW",
                    "title": "LOW-PRIORITY-INTERNAL-SENTINEL",
                    "priority_score": 20,
                    "priority_tier": "low",
                    "disposition": "reviewed",
                    "customer_visible": False,
                    "kind": "behavior",
                    "evidence_ids": ["EV-RAW-002"],
                },
            ],
            "host": [
                {
                    "evidence_id": "EV-RAW-001",
                    "observed_at": "2026-10-10T12:00:00Z",
                    "source": "elasticsearch",
                    "asset": "WS-17",
                    "observation": "RAW-HOST-EVENT-SENTINEL",
                }
            ],
            "network": [],
            "correlations": [],
            "investigation_graph": {
                "version": 1,
                "nodes": [],
                "edges": [],
                "paths": [{
                    "path_id": "PATH-001",
                    "finding_id": "F-001",
                    "title": "Suspicious PowerShell execution",
                    "confidence": "moderate",
                    "steps": [{
                        "sequence": 1,
                        "activity_type": "process_execution",
                        "label": "PowerShell launched an encoded command on WS-17",
                        "observed_at": "2026-10-10T12:00:00Z",
                        "evidence_ids": ["EV-RAW-001"],
                        "entities": [{"entity_type": "host", "value": "ws-17"}],
                    }],
                    "relationships": [],
                    "caveats": ["A single observed step does not establish a complete intrusion chain."],
                    "gaps": [],
                }],
            },
            "stage_history": [{"stage": "triage", "status": "completed", "details": "INTERNAL-STAGE-SENTINEL"}],
            "reasoning_history": [{"stage": "triage", "reasoning": "INTERNAL-REASONING-SENTINEL"}],
            "tool_runs": [{"tool": "INTERNAL-TOOL-SENTINEL", "result_status": "ok"}],
            "search_artifacts": [{"artifact_id": "INTERNAL-SEARCH-SENTINEL", "tool": "elastic.search"}],
            "search_tasks": {"ST-INTERNAL-SENTINEL": {
                "task_id": "ST-INTERNAL-SENTINEL", "source": "elasticsearch", "source_family": "host",
                "phase": "investigation", "origins": ["candidate_follow_up"],
                "intent": "Validate exact PowerShell context", "candidate_ids": ["CL-HIGH"],
                "follow_up_ids": ["FU-HIGH"], "hypothesis_ids": ["H-POWER"],
                "time_range": {"scope": "bounded test window"}, "status": "partial",
                "query_spec": {"query": {"term": {"password": "DO-NOT-REPORT-SECRET"}}},
            }},
            "search_outcomes": [{"task_id": "ST-INTERNAL-SENTINEL", "status": "partial",
                "returned_total": 5, "matched_total": 12, "capped": True, "timed_out": False,
                "shard_failures": 0, "incomplete": True, "error_kind": "ResultCap",
                "reason": "configured result cap reached", "sampling": {
                    "version": 1, "strategy": "rank_stratified", "requested_strata": 8,
                    "covered_strata": 7, "retained_by_stratum": [1, 1, 1, 1, 1, 1, 1],
                    "matched_by_stratum": [3, 3, 3, 3, 3, 3, 3],
                    "fallback_reason": "arkime_offset_limit"}}],
            "scheduler_history": [{"event": "investigation_budget_gap", "unserved_families": ["network"]}],
            "source_errors": [],
            "behavior_catalog_status": {
                "behavior_packs": {
                    "curated_total": 902,
                    "executable_curated": 636,
                    "active_direct": 73,
                    "active_sequences": 26,
                    "active_aggregates": 18,
                    "active_baselines": 43,
                    "observe_curated": 476,
                    "reference_only_curated": 266,
                    "capability_references": 1216,
                },
                "searches_executed": 7,
            },
        }

    def test_word_is_concise_customer_report_and_text_keeps_technical_record(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(self._state(), Path(directory))
            docx_path = next(path for path in paths if path.suffix == ".docx")
            text_path = next(path for path in paths if path.suffix == ".txt")
            document = Document(docx_path)
            word_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text += "\n" + "\n".join(
                cell.text for table in document.tables for row in table.rows for cell in row.cells
            )
            technical_text = text_path.read_text(encoding="utf-8")

            for expected in (
                "Assessment at a Glance",
                "Executive Summary",
                "What We Found",
                "Scope and Coverage",
                "MITRE ATT&CK Context",
                "Recommended Actions",
                "Suspicious PowerShell execution",
                "WS-17",
                "Supported Attack Path",
                "EV-RAW-001",
                "incomplete, nonrepresentative bounded retrieval",
                "Intelligence execution",
                "636 executable",
                "266 reference only",
                "Absence of findings does not prove that the environment is free of malicious activity.",
            ):
                self.assertIn(expected, word_text)

            for internal in (
                "INTERNAL-STAGE-SENTINEL",
                "INTERNAL-REASONING-SENTINEL",
                "INTERNAL-TOOL-SENTINEL",
                "INTERNAL-SEARCH-SENTINEL",
                "LOW-PRIORITY-INTERNAL-SENTINEL",
                "RAW-HOST-EVENT-SENTINEL",
                "TECHNICAL CANDIDATE WORKING LIST",
                "ST-INTERNAL-SENTINEL",
                "UNIFIED SEARCH SCHEDULER",
            ):
                self.assertNotIn(internal, word_text)
                self.assertIn(internal, technical_text)

            self.assertIn("candidate_follow_up",technical_text)
            self.assertIn("returned=5",technical_text)
            self.assertIn("matched=12",technical_text)
            self.assertIn("capped=True",technical_text)
            self.assertIn("sampling=rank_stratified",technical_text)
            self.assertIn("strata=7/8",technical_text)
            self.assertIn("retained_by_stratum=1, 1, 1, 1, 1, 1, 1",technical_text)
            self.assertIn("matched_by_stratum=3, 3, 3, 3, 3, 3, 3",technical_text)
            self.assertNotIn("sampling=rank_stratified",word_text)
            self.assertIn("CL-HIGH",technical_text)
            self.assertIn("budget-limited=ST-BUDGET-001, ST-BUDGET-002",technical_text)
            self.assertIn("total=3; omitted=1",technical_text)
            self.assertIn("Sequence analytics: loaded=89; executable=26; evaluated=2", technical_text)
            self.assertIn("Aggregate analytics: loaded=206; executable=18; evaluated=1", technical_text)
            self.assertIn("Baseline analytics: loaded=58; executable=43; evaluated=1", technical_text)
            self.assertNotIn("'by_rule':", technical_text)
            self.assertNotIn("DO-NOT-REPORT-SECRET",technical_text)

            self.assertGreaterEqual(len(document.tables), 3)
            self.assertLess(len(word_text), len(technical_text))
            self.assertNotIn("3. Validate with the asset owner.", word_text)
            self.assertIn("uncited raw evidence", technical_text)
            self.assertNotIn("complete raw evidence remains in SQLite", technical_text)

    def test_word_identifies_successful_stratified_sampling_as_representative(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report

        state = self._state()
        state["search_outcomes"][0]["sampling"].pop("fallback_reason")
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            word_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text += "\n" + "\n".join(
                cell.text for table in document.tables for row in table.rows for cell in row.cells
            )

            self.assertIn("bounded representative sample", word_text)
            self.assertNotIn("incomplete, nonrepresentative bounded retrieval", word_text)

    def test_word_calls_fallback_retrieval_incomplete_and_nonrepresentative(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report

        state = self._state()
        state["search_outcomes"][0]["sampling"].update({
            "strategy": "earliest_fallback",
            "fallback_reason": "unknown_total",
        })
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            word_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text += "\n" + "\n".join(
                cell.text for table in document.tables for row in table.rows for cell in row.cells
            )

            self.assertIn("incomplete, nonrepresentative bounded retrieval", word_text)
            self.assertNotIn("bounded representative sample", word_text)


if __name__ == "__main__":
    unittest.main()
