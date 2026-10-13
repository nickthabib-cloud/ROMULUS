import tempfile
import unittest
from pathlib import Path


class ReportItemProjectionTests(unittest.TestCase):
    def test_singular_suspicious_candidate_projects_complete_analyst_context(self):
        from romulus.reporting.report_items import build_report_items

        state = {
            "candidate_leads": [{
                "candidate_id": "CL-REVERSE-SHELL",
                "classification": "suspicious",
                "classification_reason": "A reviewed reverse-shell behavior matched.",
                "investigation_status": "follow_up_exhausted",
                "title": "Interactive reverse shell behavior",
                "description": "A shell redirected input and output to a network socket.",
                "evidence_ids": ["EV-1"],
                "assets": ["web-01"],
                "first_observed": "2026-10-12T01:00:00Z",
                "last_observed": "2026-10-12T01:00:00Z",
                "follow_ups": [{
                    "follow_up_id": "FU-1",
                    "intent": "Review the parent process and destination.",
                    "status": "blocked",
                    "history": [{"task_id": "ST-1", "status": "failed", "returned": 0}],
                }],
                "benign_explanations": ["Authorized red-team activity."],
                "telemetry_gaps": ["Parent process telemetry unavailable."],
                "attack_techniques": ["T1059"],
                "confidence": "moderate",
                "finding_ids": [],
            }],
            "findings": [],
        }

        items = build_report_items(state)

        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["classification"], "suspicious")
        self.assertEqual(item["evidence_ids"], ["EV-1"])
        self.assertEqual(item["assets"], ["web-01"])
        self.assertEqual(item["investigation_status"], "follow_up_exhausted")
        self.assertIn("failed", " ".join(item["follow_up_results"]))
        self.assertEqual(item["benign_alternatives"], ["Authorized red-team activity."])
        self.assertEqual(item["coverage_gaps"], ["Parent process telemetry unavailable."])
        self.assertEqual(item["recommended_actions"], ["Review the parent process and destination."])

    def test_anomaly_is_excluded_and_malicious_item_sorts_first(self):
        from romulus.reporting.report_items import build_report_items

        candidates = [
            {
                "candidate_id": "CL-SUSPICIOUS", "classification": "suspicious",
                "investigation_status": "new", "title": "Suspicious behavior",
                "evidence_ids": ["EV-2"], "finding_ids": [],
            },
            {
                "candidate_id": "CL-ANOMALY", "classification": "anomalous",
                "investigation_status": "new", "title": "Anomalous behavior",
                "evidence_ids": ["EV-3"], "finding_ids": [],
            },
            {
                "candidate_id": "CL-MALICIOUS", "classification": "malicious",
                "investigation_status": "resolved", "title": "Exact malicious indicator",
                "kind": "trusted_indicator", "indicator_confidence": 95,
                "indicator_id": "IOC-REPORT-ITEM",
                "indicator_source": "customer incident response", "indicator_type": "domain",
                "indicator_value": "evil.example", "indicator_match_type": "exact",
                "indicator_current_at_match": True,
                "indicator_catalog_version": "1.0.0",
                "indicator_created_at": "2026-01-01T00:00:00Z",
                "indicator_expires_at": "2027-01-01T00:00:00Z",
                "indicator_matched_at": "2026-10-10T12:00:00Z",
                "evidence_ids": ["EV-1"], "finding_ids": [],
            },
        ]

        items = build_report_items({"candidate_leads": candidates, "findings": []})

        self.assertEqual(
            [(item["item_id"], item["classification"]) for item in items],
            [("CL-MALICIOUS", "malicious"), ("CL-SUSPICIOUS", "suspicious")],
        )

    def test_only_explicit_finding_links_deduplicate_items(self):
        from romulus.reporting.report_items import build_report_items

        finding = {
            "finding_id": "F-LINKED", "title": "Evidence-backed finding",
            "observation": "Observed suspicious execution.", "interpretation": "Needs review.",
            "evidence_ids": ["EV-SHARED"], "confidence": "moderate",
            "alternatives": ["Administration."], "follow_up": ["Validate ownership."],
        }
        linked = {
            "candidate_id": "CL-LINKED", "classification": "suspicious",
            "investigation_status": "resolved", "title": "Linked candidate",
            "evidence_ids": ["EV-SHARED"], "finding_ids": ["F-LINKED"],
        }
        unlinked = {
            "candidate_id": "CL-UNLINKED", "classification": "suspicious",
            "investigation_status": "new", "title": "Separate behavior",
            "evidence_ids": ["EV-SHARED"], "finding_ids": [],
        }
        legacy_finding = {
            "finding_id": "F-LEGACY", "title": "Legacy evidence-backed lead",
            "observation": "Separate observation.", "evidence_ids": ["EV-OTHER"],
        }

        items = build_report_items({
            "candidate_leads": [linked, unlinked],
            "findings": [finding, legacy_finding],
        })

        self.assertEqual(len(items), 3)
        self.assertEqual({item["item_id"] for item in items}, {
            "F-LINKED", "CL-UNLINKED", "F-LEGACY",
        })
        linked_item = next(item for item in items if item["item_id"] == "F-LINKED")
        self.assertEqual(linked_item["candidate_ids"], ["CL-LINKED"])
        self.assertEqual(
            next(item for item in items if item["item_id"] == "F-LEGACY")["classification"],
            "suspicious",
        )


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
                    "classification": "suspicious",
                    "classification_reason": "Reviewed encoded-command behavior matched.",
                    "investigation_status": "resolved",
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
                    "finding_ids": ["F-001"],
                },
                {
                    "candidate_id": "CL-LOW",
                    "title": "LOW-PRIORITY-INTERNAL-SENTINEL",
                    "classification": "anomalous",
                    "investigation_status": "follow_up_exhausted",
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
                },
                {
                    "evidence_id": "EV-RAW-002", "source": "elasticsearch",
                    "asset": "WS-20", "observation": "LOW-PRIORITY-EVIDENCE-SENTINEL",
                },
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
        }

    def test_primary_text_uses_malicious_and_suspicious_sections_not_score_gates(self):
        from romulus.reporting.report import _content

        state = self._state()
        state["candidate_leads"].append({
            "candidate_id": "CL-MALICIOUS",
            "title": "Exact malicious domain indicator",
            "description": "A current exact trusted indicator was observed.",
            "classification": "malicious",
            "classification_reason": "Strict trusted-indicator gate passed.",
            "investigation_status": "new",
            "kind": "trusted_indicator",
            "indicator_confidence": 95,
            "indicator_id": "IOC-PRIMARY-REPORT",
            "indicator_source": "customer incident response",
            "indicator_type": "domain",
            "indicator_value": "evil.example",
            "indicator_match_type": "exact",
            "indicator_current_at_match": True,
            "indicator_catalog_version": "1.0.0",
            "indicator_created_at": "2026-01-01T00:00:00Z",
            "indicator_expires_at": "2027-01-01T00:00:00Z",
            "indicator_matched_at": "2026-10-10T12:00:00Z",
            "priority_score": 5,
            "priority_tier": "low",
            "disposition": "observed",
            "evidence_ids": ["EV-MALICIOUS"],
            "assets": ["WS-18"],
            "follow_up": ["Validate and contain if confirmed."],
            "finding_ids": [],
        })
        state["host"].append({
            "evidence_id": "EV-RAW-002", "source": "elasticsearch",
            "observed_at": "2026-10-10T13:00:00Z", "asset": "WS-20",
            "observation": "ANOMALY-EVIDENCE-SENTINEL",
        })

        text = _content(state)
        primary, technical = text.split("TECHNICAL CANDIDATE WORKING LIST", 1)

        self.assertIn("MALICIOUS BEHAVIOR", primary)
        self.assertIn("SUSPICIOUS BEHAVIOR", primary)
        self.assertLess(primary.index("Exact malicious domain indicator"), primary.index("Suspicious PowerShell execution"))
        self.assertIn("EV-MALICIOUS", primary)
        self.assertIn("EV-RAW-001", primary)
        self.assertNotIn("LOW-PRIORITY-INTERNAL-SENTINEL", primary)
        self.assertNotIn("LOW-PRIORITY-INTERNAL-SENTINEL", technical)
        self.assertNotIn("ANOMALY-EVIDENCE-SENTINEL", text)

    def test_possible_activity_narrative_is_clearly_hypothetical_and_keeps_unconnected_items(self):
        from docx import Document
        from romulus.reporting.report import generate_report

        state = self._state()
        state["activity_narrative"] = {
            "version": 1, "status": "admitted", "no_coherent_narrative": False,
            "clusters": [{
                "cluster_id": "NC-01", "item_ids": ["F-001"],
                "relationship_ids": [], "evidence_ids": ["EV-RAW-001"],
                "possible_sequence": ["F-001"],
                "narrative": "The accepted execution behavior may represent one stage of possible activity.",
                "confidence": "low", "alternate_explanations": ["Authorized administration."],
                "missing_evidence": ["No later activity was available."],
            }],
            "unconnected_item_ids": ["CL-UNCONNECTED"],
            "limitations": ["A single item cannot establish an attack path."],
        }
        state["candidate_leads"].append({
            "candidate_id": "CL-UNCONNECTED", "classification": "suspicious",
            "investigation_status": "new", "title": "Separate authentication behavior",
            "description": "An unusual but reportable authentication sequence was observed.",
            "classification_reason": "A reviewed authentication behavior matched.",
            "evidence_ids": ["EV-AUTH"], "finding_ids": [],
        })
        state["host"].append({
            "evidence_id": "EV-AUTH", "source": "elasticsearch", "asset": "WS-21",
            "observed_at": "2026-10-10T15:00:00Z", "observation": "Separate authentication sequence.",
        })

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            text = next(path for path in paths if path.suffix == ".txt" and path.parent.name != "anomalous").read_text(encoding="utf-8")
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            docx_text = "\n".join(paragraph.text for paragraph in document.paragraphs)

        self.assertIn("Hypothesis: Possible Activity Narrative", text)
        for output in (text, docx_text):
            self.assertIn("unconfirmed investigative hypothesis", output)
            self.assertIn("not a confirmed attack path", output)
        for expected in ("F-001 (Suspicious PowerShell execution)",
                         "CL-UNCONNECTED (Separate authentication behavior)",
                         "A single item cannot establish an attack path."):
            self.assertIn(expected, text)
        self.assertIn("Possible Activity Narrative", docx_text)
        self.assertIn("Suspicious PowerShell execution", docx_text)
        self.assertIn("Separate authentication behavior", docx_text)

    def test_report_revalidates_persisted_narrative_selectors_fail_closed(self):
        from docx import Document
        from romulus.reporting.report import generate_report

        state = self._state()
        state["activity_narrative"] = {
            "version": 1, "status": "admitted", "no_coherent_narrative": False,
            "clusters": [{
                "cluster_id": "NC-01",
                "item_ids": ["F-001", "NARRATIVE-UNKNOWN-ITEM"],
                "relationship_ids": ["NARRATIVE-UNKNOWN-RELATIONSHIP"],
                "evidence_ids": ["EV-RAW-001", "NARRATIVE-UNKNOWN-EVIDENCE"],
                "possible_sequence": ["F-001", "NARRATIVE-UNKNOWN-ITEM"],
                "narrative": "NARRATIVE-UNTRUSTED-PROSE",
                "confidence": "high",
                "alternate_explanations": [], "missing_evidence": [],
            }],
            "unconnected_item_ids": [], "limitations": [],
        }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            text = next(
                path for path in paths
                if path.suffix == ".txt" and path.parent.name != "anomalous"
            ).read_text(encoding="utf-8")
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            docx_text = "\n".join(paragraph.text for paragraph in document.paragraphs)

        self.assertIn("No coherent activity narrative is supported", text)
        self.assertIn("F-001 (Suspicious PowerShell execution)", text)
        self.assertIn("No model-synthesized activity narrative was available", docx_text)
        self.assertIn("Suspicious PowerShell execution", docx_text)
        for output in (text, docx_text):
            for forbidden in (
                "NARRATIVE-UNKNOWN-ITEM", "NARRATIVE-UNKNOWN-RELATIONSHIP",
                "NARRATIVE-UNKNOWN-EVIDENCE", "NARRATIVE-UNTRUSTED-PROSE",
            ):
                self.assertNotIn(forbidden, output)

    def test_unavailable_narrative_does_not_hide_factual_behavior(self):
        from romulus.reporting.report import _content

        state = self._state()
        state["activity_narrative"] = {
            "version": 1, "status": "unavailable", "no_coherent_narrative": True,
            "clusters": [], "unconnected_item_ids": ["F-001"], "limitations": [],
            "reason": "The narrative model was unavailable.",
        }

        text = _content(state)

        self.assertIn("Suspicious PowerShell execution", text)
        self.assertIn("No coherent activity narrative is supported", text)
        self.assertIn("F-001 (Suspicious PowerShell execution)", text)

    def test_finalized_anomaly_report_is_separate_bounded_and_analyst_readable(self):
        from romulus.reporting.report import generate_report

        state = self._state()
        state["findings"] = []
        state["candidate_leads"] = [{
            "candidate_id": "CL-ANOMALOUS",
            "title": "Unusual temporary execution",
            "description": "A process executed from a temporary path.",
            "classification": "anomalous",
            "classification_reason": "The behavior is unusual but needs independent evidence.",
            "investigation_status": "follow_up_exhausted",
            "evidence_ids": ["EV-ANOMALOUS"],
            "benign_explanations": ["A software installer may use a temporary path."],
            "telemetry_gaps": ["Parent process telemetry was unavailable."],
            "follow_ups": [{
                "follow_up_id": "FU-ANOMALOUS",
                "intent": "Review the parent process and signer.",
                "status": "blocked",
                "history": [{"task_id": "ST-ANOMALOUS", "status": "failed", "returned": 0}],
            }],
            "finding_ids": [],
        }]
        state["host"] = [{
            "evidence_id": "EV-ANOMALOUS",
            "source": "elasticsearch",
            "observed_at": "2026-10-10T12:34:56Z",
            "asset": "WS-22",
            "observation": "Unsigned process launched from a temporary directory.",
            "provenance": {"search_id": "ST-ANOMALOUS", "index": "host-events", "query": "RAW-QUERY-SECRET"},
            "raw": {"packet_payload": "RAW-PACKET-SECRET", "password": "CREDENTIAL-SECRET"},
        }]
        state["search_tasks"] = {"ST-ANOMALOUS": {
            "task_id": "ST-ANOMALOUS", "candidate_ids": ["CL-ANOMALOUS"],
            "follow_up_ids": ["FU-ANOMALOUS"], "intent": "Review signer context.",
            "query_spec": {"password": "TASK-QUERY-SECRET"},
        }}
        state["search_outcomes"] = [{
            "task_id": "ST-ANOMALOUS", "status": "failed", "returned_total": 0,
            "matched_total": 0, "reason": "source unavailable",
        }]
        state["reasoning_history"] = [{"private": "MODEL-INTERNAL-SECRET"}]

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            anomaly_path = next(path for path in paths if path.parent.name == "anomalous")
            anomaly = anomaly_path.read_text(encoding="utf-8")

        self.assertEqual(len(paths), 3)
        self.assertTrue(state["report_manifest"]["anomaly_expected"])
        self.assertIn(state["report_manifest"]["generation_stamp"], anomaly_path.name)
        for expected in (
            "Investigation: HUNT-CUSTOMER",
            "Hunt window: 2026-10-10T00:00:00Z through 2026-10-11T00:00:00Z",
            "CL-ANOMALOUS",
            "EV-ANOMALOUS",
            "Unsigned process launched from a temporary directory.",
            "Why unusual",
            "Performed searches and outcomes",
            "A software installer may use a temporary path.",
            "Parent process telemetry was unavailable.",
            "Review the parent process and signer.",
            "lead, not a conclusion",
        ):
            self.assertIn(expected, anomaly)
        for forbidden in (
            "RAW-QUERY-SECRET", "RAW-PACKET-SECRET", "CREDENTIAL-SECRET",
            "TASK-QUERY-SECRET", "MODEL-INTERNAL-SECRET", "query_spec",
        ):
            self.assertNotIn(forbidden, anomaly)

    def test_finalized_primary_omits_anomaly_only_working_sections(self):
        from romulus.reporting.report import generate_report

        state = self._state()
        anomaly = state["candidate_leads"][1]
        anomaly.update({
            "title": "ANOMALY-TITLE-SENTINEL",
            "description": "ANOMALY-DESCRIPTION-SENTINEL",
            "evidence_ids": ["EV-ANOMALY-SENTINEL"],
            "follow_ups": [{"follow_up_id": "FU-ANOMALY", "status": "completed",
                "intent": "ANOMALY-FOLLOWUP-SENTINEL", "history": []}],
        })
        state["host"].append({
            "evidence_id": "EV-ANOMALY-SENTINEL", "source": "elasticsearch",
            "observation": "ANOMALY-EVIDENCE-SENTINEL", "asset": "ANOMALY-ASSET-SENTINEL",
        })
        state["hypotheses"].append({
            "hypothesis_id": "H-ANOMALY", "candidate_id": anomaly["candidate_id"],
            "title": "ANOMALY-HYPOTHESIS-SENTINEL", "rationale": "ANOMALY-RATIONALE-SENTINEL",
        })
        state["analytic_summary"] = {"behavioral_observations": [{
            "analytic": "ANOMALY-ANALYTIC-SENTINEL",
            "sample_evidence_ids": ["EV-ANOMALY-SENTINEL"],
        }]}
        state["correlations"] = [{
            "host_ref": "EV-ANOMALY-SENTINEL", "network_ref": "EV-ANOMALY-SENTINEL",
            "reasons": ["ANOMALY-CORRELATION-SENTINEL"],
        }]
        state["reasoning_history"].append({"reasoning": "ANOMALY-REASONING-SENTINEL"})
        state["search_artifacts"].append({"artifact_id": "ANOMALY-ARTIFACT-SENTINEL"})
        state["search_tasks"]["ST-ANOMALY"] = {
            "task_id": "ST-ANOMALY", "candidate_ids": [anomaly["candidate_id"]],
            "intent": "ANOMALY-TASK-SENTINEL", "status": "completed",
        }

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            primary = next(path for path in paths
                if path.suffix == ".txt" and path.parent.name != "anomalous").read_text(encoding="utf-8")
            anomaly_text = next(path for path in paths
                if path.parent.name == "anomalous").read_text(encoding="utf-8")

        for sentinel in (
            "ANOMALY-TITLE-SENTINEL", "ANOMALY-DESCRIPTION-SENTINEL",
            "ANOMALY-EVIDENCE-SENTINEL", "ANOMALY-ASSET-SENTINEL",
            "ANOMALY-HYPOTHESIS-SENTINEL", "ANOMALY-RATIONALE-SENTINEL",
            "ANOMALY-ANALYTIC-SENTINEL", "ANOMALY-CORRELATION-SENTINEL",
            "ANOMALY-REASONING-SENTINEL", "ANOMALY-ARTIFACT-SENTINEL",
            "ANOMALY-TASK-SENTINEL", "ANOMALY-FOLLOWUP-SENTINEL",
        ):
            self.assertNotIn(sentinel, primary)
        self.assertIn("ANOMALY-TITLE-SENTINEL", anomaly_text)
        self.assertIn("ANOMALY-EVIDENCE-SENTINEL", anomaly_text)
        self.assertIn("ANOMALY-TASK-SENTINEL", anomaly_text)

    def test_report_generation_fails_when_reportable_citation_is_unresolvable(self):
        from romulus.reporting.report import generate_report

        state = self._state()
        state["findings"][0]["evidence_ids"] = ["EV-DOES-NOT-EXIST"]
        state["candidate_leads"][0]["evidence_ids"] = ["EV-DOES-NOT-EXIST"]

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            with self.assertRaisesRegex(ValueError, "EV-DOES-NOT-EXIST"):
                generate_report(state, Path(directory))
            self.assertEqual(list(Path(directory).rglob("*")), [])

    def test_anomaly_report_requires_finalization_and_unresolved_anomalies(self):
        from romulus.reporting.report import generate_report

        base = self._state()
        base["findings"] = []
        base["candidate_leads"] = [{
            "candidate_id": "CL-ANOMALOUS", "classification": "anomalous",
            "investigation_status": "new", "title": "Unresolved anomaly",
            "evidence_ids": ["EV-RAW-001"], "finding_ids": [],
        }]

        cases = []
        partial = dict(base, status="partial")
        cases.append(("resumable partial", partial, False))
        finalized = dict(base, status="partial", finalized_at="2026-10-13T00:00:00Z")
        cases.append(("finalized partial", finalized, True))
        resolved = dict(base, candidate_leads=[dict(base["candidate_leads"][0], investigation_status="resolved")])
        cases.append(("resolved anomaly", resolved, False))
        reportable = dict(base, candidate_leads=[dict(
            base["candidate_leads"][0], classification="suspicious"
        )])
        cases.append(("reportable only", reportable, False))

        for label, state, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                dir=Path(__file__).resolve().parent
            ) as directory:
                paths = generate_report(state, Path(directory))
                self.assertEqual(len(paths), 3 if expected else 2)
                self.assertEqual(state["report_manifest"]["anomaly_expected"], expected)

    def test_technical_report_records_reasoning_admission_and_critic_gap_aggregates(self):
        from romulus.reporting.report import _content

        state = self._state()
        state["coverage"]["reasoning_summary"] = {
            "investigator_calls": 3, "critic_calls": 2, "unavailable_passes": 1,
            "proposed_hypotheses": 4, "admitted_hypotheses": 1, "rejected_hypotheses": 3,
            "proposed_assessments": 3, "admitted_assessments": 2, "rejected_assessments": 1,
            "proposed_searches": 5, "admitted_searches": 2, "rejected_searches": 3,
            "proposed_findings": 2, "admitted_findings": 1, "rejected_findings": 1,
            "last_gap": "critic_unavailable",
        }
        state["reasoning_history"] = [{
            "stage": "analyst_reasoning", "basis": "grounded review", "round": 1,
            "grounded_reasoning": {
                "case_file": {"private": "CASE-FILE-PAYLOAD-SENTINEL"},
                "investigator": {"proposal_id": "PROPOSAL-PAYLOAD-SENTINEL"},
                "critic": {"reviews": ["CRITIC-PAYLOAD-SENTINEL"]},
                "admission": {"rejections": [
                    {"proposal_id": "P-HIDDEN-1", "reason_codes": ["critic_not_approved"]},
                    {"proposal_id": "P-HIDDEN-2", "reason_codes": ["missing_anchor", "critic_not_approved"]},
                ]},
            },
        }]

        technical_text = _content(state)

        self.assertIn("INVESTIGATOR AND CRITIC COVERAGE", technical_text)
        self.assertIn("investigator=3; critic=2; unavailable passes=1", technical_text)
        self.assertIn("Hypotheses: proposed=4; admitted=1; rejected=3", technical_text)
        self.assertIn("Searches: proposed=5; admitted=2; rejected=3", technical_text)
        self.assertIn("critic_not_approved=2", technical_text)
        self.assertIn("missing_anchor=1", technical_text)
        self.assertIn("Availability gaps: critic_unavailable", technical_text)
        for internal in ("P-HIDDEN-1", "CASE-FILE-PAYLOAD-SENTINEL",
                "PROPOSAL-PAYLOAD-SENTINEL", "CRITIC-PAYLOAD-SENTINEL"):
            self.assertNotIn(internal, technical_text)

    def test_customer_report_omits_case_file_proposal_and_critic_internals(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report

        state = self._state()
        state["coverage"]["reasoning_summary"] = {
            "investigator_calls": 1, "critic_calls": 1,
            "proposed_searches": 1, "admitted_searches": 0, "rejected_searches": 1,
        }
        state["reasoning_history"].append({"stage": "analyst_reasoning",
            "grounded_reasoning": {
                "case_file": {"private": "CUSTOMER-CASE-FILE-SENTINEL"},
                "investigator": {"proposal_id": "CUSTOMER-PROPOSAL-SENTINEL"},
                "critic": {"reviews": ["CUSTOMER-CRITIC-SENTINEL"]},
            }})

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths = generate_report(state, Path(directory))
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            word_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text += "\n" + "\n".join(
                cell.text for table in document.tables for row in table.rows for cell in row.cells
            )

        for internal in ("INVESTIGATOR AND CRITIC COVERAGE", "investigator_calls",
                "CUSTOMER-CASE-FILE-SENTINEL", "CUSTOMER-PROPOSAL-SENTINEL",
                "CUSTOMER-CRITIC-SENTINEL"):
            self.assertNotIn(internal, word_text)

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
                "Strong Indicators",
                "Supporting Context",
                "Likely Noise or Misclassified Activity",
                "Possible Activity Narrative",
                "Scope and Coverage",
                "MITRE ATT&CK Context",
                "Recommended Follow-ups",
                "Suspicious PowerShell execution",
                "WS-17",
                "EV-RAW-001",
                "incomplete, nonrepresentative bounded retrieval",
            ):
                self.assertIn(expected, word_text)

            for internal in (
                "INTERNAL-STAGE-SENTINEL",
                "INTERNAL-REASONING-SENTINEL",
                "INTERNAL-TOOL-SENTINEL",
                "INTERNAL-SEARCH-SENTINEL",
                "RAW-HOST-EVENT-SENTINEL",
                "TECHNICAL CANDIDATE WORKING LIST",
                "ST-INTERNAL-SENTINEL",
                "UNIFIED SEARCH SCHEDULER",
            ):
                self.assertNotIn(internal, word_text)
            for removed_working_detail in (
                "INTERNAL-STAGE-SENTINEL", "INTERNAL-REASONING-SENTINEL",
                "INTERNAL-TOOL-SENTINEL", "INTERNAL-SEARCH-SENTINEL",
            ):
                self.assertNotIn(removed_working_detail, technical_text)
            for retained_reportable_detail in (
                "RAW-HOST-EVENT-SENTINEL", "TECHNICAL CANDIDATE WORKING LIST",
                "ST-INTERNAL-SENTINEL", "UNIFIED SEARCH SCHEDULER",
            ):
                self.assertIn(retained_reportable_detail, technical_text)

            self.assertNotIn("LOW-PRIORITY-INTERNAL-SENTINEL", word_text)
            self.assertNotIn("LOW-PRIORITY-INTERNAL-SENTINEL", technical_text)

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
            self.assertNotIn("ST-BUDGET-001",technical_text)
            self.assertNotIn("DO-NOT-REPORT-SECRET",technical_text)

            self.assertGreaterEqual(len(document.tables), 3)
            self.assertLess(len(word_text), len(technical_text))
            self.assertNotIn("3. Validate with the asset owner.", word_text)
            self.assertIn("uncited raw evidence", technical_text)
            self.assertNotIn("complete raw evidence remains in SQLite", technical_text)

    def test_word_renders_admitted_indicator_brief_with_exact_artifacts_and_keeps_txt_exhaustive(self):
        from docx import Document
        from romulus.reporting.indicator_review import admit_indicator_review, build_indicator_case
        from romulus.reporting.report import generate_report
        from romulus.reporting.report_items import build_report_items

        state = self._state()
        state["host"][0]["observation"] = (
            "WS-17 ran an encoded command and queried transfer.example for payroll.xlsx."
        )
        state["host"][0]["raw"] = {
            "process.command_line": "powershell.exe -enc QUJD",
            "process.name": "powershell.exe",
            "dns.question.name": "transfer.example",
            "file.name": "payroll.xlsx",
            "source.ip": "10.10.10.17",
        }
        state["candidate_leads"].append({
            "candidate_id": "CL-WEB", "title": "Download followed by execution",
            "description": "A tool-like web path was requested.",
            "classification": "suspicious", "classification_reason": "A keyword analytic matched.",
            "investigation_status": "follow_up_exhausted", "kind": "behavior",
            "evidence_ids": ["EV-WEB"], "finding_ids": [],
            "benign_explanations": ["Directory enumeration."],
            "follow_up": ["Review adjacent web requests."],
        })
        state["host"].append({
            "evidence_id": "EV-WEB", "source": "elasticsearch", "asset": "web-01",
            "observed_at": "2026-10-10T12:05:00Z",
            "observation": "GET /wget returned 404 during directory enumeration.",
            "raw": {"http.uri": "/wget", "http.status_code": 404,
                    "source.ip": "10.10.10.18"},
        })
        report_items = build_report_items(state)
        case = build_indicator_case(state, report_items)
        strong_item = next(row for row in case["items"] if row["item_id"] == "F-001")
        strong_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-RAW-001")
        noise_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-WEB")
        state["indicator_review"] = admit_indicator_review(case, {
            "strong_indicators": [{
                "item_ids": [strong_item["item_id"]], "evidence_ids": ["EV-RAW-001"],
                "observable_ids": [row["observable_id"] for row in strong_evidence["observables"]],
                "relationship_ids": [], "title": "Encoded script execution with DNS activity",
                "assessment": "The combined process and DNS behavior warrants immediate analyst review.",
                "limitations": ["Process ancestry was not available."],
                "recommended_follow_ups": ["Validate the command with the asset owner."],
                "confidence": "high", "outcome": "suspected",
            }],
            "supporting_context": [{
                "item_ids": [strong_item["item_id"]], "evidence_ids": ["EV-RAW-001"],
                "observable_ids": [row["observable_id"] for row in strong_evidence["observables"]],
                "relationship_ids": [],
                "assessment": "The command, host, file reference, and DNS name appear in one canonical record.",
                "limitations": ["No second sensor corroborated the record."],
            }],
            "likely_noise": [{
                "item_ids": ["CL-WEB"], "evidence_ids": ["EV-WEB"],
                "observable_ids": [row["observable_id"] for row in noise_evidence["observables"]],
                "relationship_ids": [], "title": "Failed tool-like web path probe",
                "assessment": "The 404 response supports enumeration, not successful download or execution.",
                "limitations": [], "recommended_follow_ups": ["Review adjacent requests if needed."],
            }],
            "possible_activity_narrative": {
                "item_ids": [strong_item["item_id"]], "relationship_ids": [],
                "summary": "One suspicious execution and DNS activity cluster may warrant a focused follow-up.",
                "limitations": ["A single record does not establish a complete attack path."],
            },
            "recommended_follow_ups": ["Validate the encoded command and originating account."],
        })
        self.assertEqual(state["indicator_review"]["status"], "admitted")

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            report_root = Path(directory) / "reports"
            paths = generate_report(state, report_root)
            document = Document(next(path for path in paths if path.suffix == ".docx"))
            word_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text += "\n" + "\n".join(
                cell.text for table in document.tables for row in table.rows for cell in row.cells
            )
            technical_text = next(path for path in paths if path.suffix == ".txt").read_text(encoding="utf-8")

        for heading in ("Strong Indicators", "Supporting Context",
                        "Likely Noise or Misclassified Activity", "Possible Activity Narrative",
                        "Recommended Follow-ups"):
            self.assertIn(heading, word_text)
        for artifact in ("powershell.exe -enc QUJD", "transfer.example", "payroll.xlsx",
                         "10.10.10.17", "/wget", "404", "EV-RAW-001", "EV-WEB"):
            self.assertIn(artifact, word_text)
        self.assertIn("supports enumeration, not successful download or execution", word_text)
        self.assertNotIn("What We Found", word_text)
        self.assertNotIn("Follow-up results:", word_text)
        self.assertIn("SUSPICIOUS BEHAVIOR", technical_text)
        self.assertIn("TECHNICAL CANDIDATE WORKING LIST", technical_text)

    def test_generated_manifest_and_every_report_path_stay_under_supplied_reports_root(self):
        from romulus.reporting.report import generate_report

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            report_root = Path(directory) / "reports"
            state = self._state()
            paths = generate_report(state, report_root)
            resolved_root = report_root.resolve()

            self.assertEqual(Path(state["report_manifest"]["report_root"]), resolved_root)
            self.assertTrue(all(resolved_root in path.resolve().parents for path in paths))

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

    def test_technical_report_explains_progress_stop_and_emergency_backstops(self):
        from romulus.reporting.report import generate_report

        state=self._state()
        state.update({"status":"partial","termination_reason":"no_productive_frontier",
            "duration_ms":42000,"tool_calls":7,"depth":3})
        state["coverage"].update({
            "runtime_seconds_used":42.0,"runtime_seconds_limit":3600,
            "tool_call_limit":500,"depth_limit":40,"max_stagnant_cycles":3,
            "stagnant_cycles":3,"progress_summary":{"cycles_recorded":5,
                "productive_cycles":2,"stagnant_cycles_recorded":3,
                "current_stagnant_cycles":3,"max_stagnant_cycles_seen":3,
                "signal_totals":{"new_evidence":2},"last_stage":"analysis",
                "last_material_signals":{},"final_stop_basis":"no_productive_frontier"},
        })
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths=generate_report(state,Path(directory))
            technical=next(path for path in paths if path.suffix==".txt").read_text(encoding="utf-8")

        self.assertIn("Progress stop basis: no_productive_frontier",technical)
        self.assertIn("Progress cycles: 5 recorded; 2 productive; 3 stagnant",technical)
        self.assertIn("Stagnation: current=3; maximum observed=3; configured stop threshold=3",technical)
        self.assertIn("Safety backstops: runtime=42.0 / 3600 seconds; tool calls=7 / 500; analyst rounds=3 / 40",technical)

    def test_customer_report_uses_plain_language_without_progress_internals(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report

        state=self._state()
        state.update({"status":"partial","termination_reason":"no_productive_frontier",
            "progress_baseline":{"changed_ids":["INTERNAL-BASELINE-SENTINEL"]},
            "progress_history":[{"changed_ids":{"new_evidence":["INTERNAL-PROGRESS-SENTINEL"]}}]})
        state["coverage"].update({"coverage_closure_ready":False,"stagnant_cycles":3,
            "max_stagnant_cycles":3,"progress_summary":{"cycles_recorded":3,
                "productive_cycles":0,"stagnant_cycles_recorded":3,
                "final_stop_basis":"no_productive_frontier"}})
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            paths=generate_report(state,Path(directory))
            document=Document(next(path for path in paths if path.suffix==".docx"))
            word_text="\n".join(paragraph.text for paragraph in document.paragraphs)
            word_text+="\n"+"\n".join(cell.text for table in document.tables for row in table.rows for cell in row.cells)

        self.assertIn("ended because no further productive evidence pivot was available",word_text)
        self.assertIn("No finding is not proof that the environment is free of malicious activity",word_text)
        for internal in ("progress_baseline","progress_history","changed_ids",
                "INTERNAL-BASELINE-SENTINEL","INTERNAL-PROGRESS-SENTINEL"):
            self.assertNotIn(internal,word_text)


if __name__ == "__main__":
    unittest.main()
