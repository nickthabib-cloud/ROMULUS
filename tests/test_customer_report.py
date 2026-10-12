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
            "duration_ms": 42000,
            "tool_calls": 7,
            "depth": 3,
            "coverage": {
                "time_scope": "2026-10-10T00:00:00Z through 2026-10-11T00:00:00Z",
                "host": "available; 123 events examined",
                "network": "available; 18 sessions examined",
                "tool_call_limit": 20,
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
            "stage_history": [{"stage": "triage", "status": "completed", "details": "INTERNAL-STAGE-SENTINEL"}],
            "reasoning_history": [{"stage": "triage", "reasoning": "INTERNAL-REASONING-SENTINEL"}],
            "tool_runs": [{"tool": "INTERNAL-TOOL-SENTINEL", "result_status": "ok"}],
            "search_artifacts": [{"artifact_id": "INTERNAL-SEARCH-SENTINEL", "tool": "elastic.search"}],
            "source_errors": [],
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
            ):
                self.assertNotIn(internal, word_text)
                self.assertIn(internal, technical_text)

            self.assertGreaterEqual(len(document.tables), 3)
            self.assertLess(len(word_text), len(technical_text))
            self.assertNotIn("3. Validate with the asset owner.", word_text)


if __name__ == "__main__":
    unittest.main()
