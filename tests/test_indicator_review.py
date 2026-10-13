import copy
import importlib
import sys
import tempfile
import time
import types
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


@contextmanager
def _ollama_module():
    requests_stub = types.ModuleType("requests")
    requests_stub.Session = lambda: None
    sys.modules.pop("romulus.agent.ollama", None)
    with patch.dict(sys.modules, {"requests": requests_stub}):
        try:
            yield importlib.import_module("romulus.agent.ollama")
        finally:
            sys.modules.pop("romulus.agent.ollama", None)


def _state():
    return {
        "hunt_id": "HUNT-INDICATORS",
        "objective": "Broad evidence-led hunt.",
        "coverage": {
            "time_scope": "2022-01-24T03:00:00Z through 2022-01-24T05:00:00Z",
            "host": "available",
            "network": "partial",
        },
        "host": [{
            "evidence_id": "EV-WEB",
            "source": "elasticsearch",
            "asset": "web-01",
            "observed_at": "2022-01-24T03:57:38Z",
            "observation": "GET /wget returned 404 during directory enumeration by dirb.",
            "raw": {
                "http.request.method": "GET",
                "http.uri": "/wget",
                "http.status_code": 404,
                "user_agent.original": "dirb/2.22",
                "source.ip": "172.19.131.174",
                "destination.ip": "10.143.2.4",
            },
            "provenance": {
                "search_id": "ST-WEB",
                "index": "host-events",
                "document_id": "DOC-WEB",
                "path": "gather/attacker_0/logs/answer-revealing.log",
            },
            "ait": {
                "ground_truth_available": True,
                "ground_truth": {"labels": ["attacker", "dirb"], "rules": {"answer": ["rule"]}},
            },
        }],
        "network": [{
            "evidence_id": "EV-DNS-1",
            "source": "arkime",
            "asset": "share-01",
            "observed_at": "2022-01-24T04:02:25Z",
            "observation": "Long sequenced DNS label observed.",
            "raw": {
                "dns.qry.name": "3x6-.254-.abc-.quarterly.xlsx.transfer.example",
                "source.ip": "10.143.0.103",
                "destination.ip": "192.168.230.122",
                "destination.port": 53,
                "network.protocol": "dns",
            },
            "provenance": {"search_id": "ST-DNS-1", "session_id": "S-1"},
        }, {
            "evidence_id": "EV-DNS-2",
            "source": "tshark",
            "asset": "share-01",
            "observed_at": "2022-01-24T04:02:27Z",
            "observation": "The same DNS query was visible at a second sensor.",
            "raw": {
                "dns.qry.name": "3x6-.254-.abc-.quarterly.xlsx.transfer.example",
                "source.ip": "10.143.0.103",
                "destination.ip": "192.168.230.122",
                "destination.port": 53,
            },
            "provenance": {
                "search_id": "ST-DNS-2",
                "pcap": "/captures/scenario-answer-dnsteal.pcap",
            },
        }, {
            "evidence_id": "EV-UNOWNED",
            "source": "elasticsearch",
            "asset": "secret-host",
            "observed_at": "2022-01-24T04:03:00Z",
            "observation": "This record is not owned by a report item.",
            "raw": {"message": "SECRET-ANSWER"},
            "ait": {"ground_truth": {"labels": ["malicious"]}},
        }],
        "correlations": [{
            "correlation_id": "COR-DNS",
            "host_ref": "EV-DNS-1",
            "network_ref": "EV-DNS-2",
            "reason": "same normalized DNS query",
            "score": 0.95,
        }, {
            "correlation_id": "COR-UNOWNED",
            "host_ref": "EV-UNOWNED",
            "network_ref": "EV-DNS-1",
            "reason": "must not escape",
        }],
    }


def _items():
    return [{
        "item_id": "CL-DNS",
        "candidate_ids": ["CL-DNS"],
        "classification": "suspicious",
        "title": "Repeated encoded DNS label burst",
        "observation": "Several long DNS labels shared a suffix.",
        "why_it_matters": "The bounded pattern warrants analyst review.",
        "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
        "assets": ["share-01"],
        "first_observed": "2022-01-24T04:02:25Z",
        "last_observed": "2022-01-24T04:02:27Z",
        "investigation_status": "follow_up_exhausted",
        "follow_up_results": [],
        "benign_alternatives": ["Authorized DNS tunnel."],
        "coverage_gaps": ["Endpoint process attribution unavailable."],
        "recommended_actions": ["Identify the originating process and user."],
        "confidence": "moderate",
        "attack_techniques": ["T1071.004"],
    }, {
        "item_id": "CL-WEB",
        "candidate_ids": ["CL-WEB"],
        "classification": "suspicious",
        "title": "Download followed by an execution-oriented command",
        "observation": "A tool-like path appeared in an HTTP request.",
        "why_it_matters": "Requires validation.",
        "evidence_ids": ["EV-WEB"],
        "assets": ["web-01"],
        "first_observed": "2022-01-24T03:57:38Z",
        "last_observed": "2022-01-24T03:57:38Z",
        "investigation_status": "follow_up_exhausted",
        "follow_up_results": [],
        "benign_alternatives": ["Directory enumeration."],
        "coverage_gaps": [],
        "recommended_actions": ["Review adjacent web requests."],
        "confidence": "not assessed",
        "attack_techniques": ["T1105"],
    }]


def _proposal(case):
    dns_observables = [
        row["observable_id"] for evidence in case["evidence"]
        if evidence["evidence_id"] in {"EV-DNS-1", "EV-DNS-2"}
        for row in evidence["observables"]
        if row["type"] in {"domain", "ip", "port"}
    ]
    return {
        "strong_indicators": [{
            "item_ids": ["CL-DNS"],
            "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
            "observable_ids": dns_observables,
            "relationship_ids": ["COR-DNS"],
            "title": "Sequenced encoded DNS activity",
            "assessment": "Repeated sequenced labels are consistent with an encoded DNS channel.",
            "limitations": ["Endpoint process attribution is unavailable."],
            "recommended_follow_ups": ["Identify the originating process and account."],
            "confidence": "high",
            "outcome": "suspected",
        }],
        "supporting_context": [{
            "item_ids": ["CL-DNS"],
            "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
            "observable_ids": dns_observables,
            "relationship_ids": ["COR-DNS"],
            "title": "Two sensors observed the same query",
            "assessment": "The admitted relationship provides cross-sensor support.",
            "limitations": [],
            "recommended_follow_ups": [],
            "confidence": "moderate",
            "outcome": "observed",
        }],
        "likely_noise": [{
            "item_ids": ["CL-WEB"],
            "evidence_ids": ["EV-WEB"],
            "observable_ids": [],
            "relationship_ids": [],
            "title": "Tool-like path was a failed probe",
            "assessment": "The HTTP response was 404, so this supports enumeration rather than successful download.",
            "limitations": [],
            "recommended_follow_ups": [],
            "confidence": "high",
            "outcome": "observed",
        }],
        "possible_activity_narrative": {
            "item_ids": ["CL-DNS"],
            "relationship_ids": ["COR-DNS"],
            "summary": "The evidence may represent one bounded encoded-DNS activity cluster.",
            "limitations": ["Endpoint process attribution is unavailable."],
        },
        "recommended_follow_ups": ["Identify the process that generated the queries."],
    }


class IndicatorCaseTests(unittest.TestCase):
    def test_case_owns_evidence_extracts_observables_and_scrubs_answers(self):
        from romulus.reporting.indicator_review import build_indicator_case

        case = build_indicator_case(_state(), _items())

        self.assertEqual({row["evidence_id"] for row in case["evidence"]}, {
            "EV-DNS-1", "EV-DNS-2", "EV-WEB",
        })
        rendered = repr(case).lower()
        self.assertNotIn("ground_truth", rendered)
        self.assertNotIn("answer-revealing", rendered)
        self.assertNotIn("scenario-answer", rendered)
        self.assertNotIn("secret-answer", rendered)
        observables = {
            (row["type"], row["value"])
            for evidence in case["evidence"]
            for row in evidence["observables"]
        }
        self.assertIn(("domain", "3x6-.254-.abc-.quarterly.xlsx.transfer.example"), observables)
        self.assertIn(("ip", "10.143.0.103"), observables)
        self.assertIn(("port", "53"), observables)
        self.assertIn(("url_path", "/wget"), observables)
        self.assertIn(("http_status", "404"), observables)
        self.assertEqual([row["relationship_id"] for row in case["relationships"]], ["COR-DNS"])


class IndicatorAdmissionTests(unittest.TestCase):
    def _case(self):
        from romulus.reporting.indicator_review import build_indicator_case
        return build_indicator_case(_state(), _items())

    def test_admission_resolves_canonical_artifacts_and_consolidates_duplicates(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        dns_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] in {"EV-DNS-1", "EV-DNS-2"}
            for row in evidence["observables"]
            if row["type"] in {"domain", "ip", "port"}
        ]
        second_sensor_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] == "EV-DNS-2"
            for row in evidence["observables"]
            if row["type"] in {"domain", "ip", "port"}
        ]
        proposal = {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"],
                "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
                "observable_ids": dns_observables,
                "relationship_ids": ["COR-DNS"],
                "title": "Sequenced encoded DNS activity",
                "assessment": "Repeated sequenced labels are consistent with an encoded DNS channel.",
                "limitations": ["Endpoint process attribution is unavailable."],
                "recommended_follow_ups": ["Identify the originating process and account."],
                "confidence": "high",
                "outcome": "suspected",
            }, {
                "item_ids": ["CL-DNS"],
                "evidence_ids": ["EV-DNS-2"],
                "observable_ids": second_sensor_observables,
                "relationship_ids": ["COR-DNS"],
                "title": "Duplicate sensor view",
                "assessment": "Second sensor view of the same activity.",
                "limitations": [],
                "recommended_follow_ups": [],
                "confidence": "moderate",
                "outcome": "suspected",
            }],
            "supporting_context": [],
            "likely_noise": [],
            "possible_activity_narrative": {
                "item_ids": ["CL-DNS"],
                "relationship_ids": ["COR-DNS"],
                "summary": "The observations may represent one bounded DNS activity cluster.",
                "limitations": ["Process attribution is unavailable."],
            },
            "recommended_follow_ups": ["Identify the process that generated the queries."],
        }

        admitted = admit_indicator_review(case, proposal)

        self.assertEqual(admitted["status"], "admitted")
        self.assertEqual(len(admitted["strong_indicators"]), 1)
        indicator = admitted["strong_indicators"][0]
        self.assertEqual(indicator["evidence_ids"], ["EV-DNS-1", "EV-DNS-2"])
        self.assertIn("3x6-.254-.abc-.quarterly.xlsx.transfer.example", {
            row["value"] for row in indicator["artifacts"]
        })
        self.assertEqual(indicator["assets"], ["share-01"])

    def test_unknown_selector_rejects_the_entire_proposal(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        rejected = admit_indicator_review(self._case(), {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"], "evidence_ids": ["EV-NOT-REAL"],
                "observable_ids": ["OB-NOT-REAL"], "relationship_ids": [],
                "title": "Invented indicator", "assessment": "Invented artifact evil.example.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "high", "outcome": "confirmed",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["strong_indicators"], [])
        self.assertIn("unknown_evidence_id", rejected["rejection_codes"])

    def test_http_404_path_probe_cannot_support_confirmed_download(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        web_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] == "EV-WEB"
            for row in evidence["observables"]
        ]
        rejected = admit_indicator_review(case, {
            "strong_indicators": [{
                "item_ids": ["CL-WEB"], "evidence_ids": ["EV-WEB"],
                "observable_ids": web_observables, "relationship_ids": [],
                "title": "Successful payload download and execution",
                "assessment": "The payload was downloaded and executed.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "high", "outcome": "confirmed",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("unsupported_confirmed_outcome", rejected["rejection_codes"])

    def test_valid_selectors_cannot_smuggle_an_invented_observable_in_prose(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        dns_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-DNS-1")
        rejected = admit_indicator_review(case, {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"], "evidence_ids": ["EV-DNS-1"],
                "observable_ids": [row["observable_id"] for row in dns_evidence["observables"]],
                "relationship_ids": [], "title": "DNS indicator for evil.example",
                "assessment": "The selected evidence contacted evil.example.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "high", "outcome": "suspected",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("unsupported_text_observable", rejected["rejection_codes"])

    def test_failed_http_response_rejects_asserted_success_even_when_outcome_is_suspected(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        web_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-WEB")
        rejected = admit_indicator_review(case, {
            "strong_indicators": [{
                "item_ids": ["CL-WEB"], "evidence_ids": ["EV-WEB"],
                "observable_ids": [row["observable_id"] for row in web_evidence["observables"]],
                "relationship_ids": [], "title": "Successful payload execution",
                "assessment": "The payload was downloaded and executed.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "moderate", "outcome": "suspected",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("contradicted_success_claim", rejected["rejection_codes"])

    def test_deterministic_fallback_preserves_reportable_items_and_artifacts(self):
        from romulus.reporting.indicator_review import deterministic_indicator_review

        fallback = deterministic_indicator_review(self._case(), "model unavailable")

        self.assertEqual(fallback["status"], "fallback")
        self.assertEqual({row["item_ids"][0] for row in fallback["strong_indicators"]}, {
            "CL-DNS", "CL-WEB",
        })
        self.assertTrue(any(row["artifacts"] for row in fallback["strong_indicators"]))
        self.assertEqual(fallback["reason"], "model unavailable")

    def test_persisted_selectors_are_rejected_when_canonical_evidence_changes(self):
        from romulus.reporting.indicator_review import (
            admit_indicator_review, indicator_review_proposal,
        )

        case = self._case()
        dns_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-DNS-1")
        proposal = {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"], "evidence_ids": ["EV-DNS-1"],
                "observable_ids": [row["observable_id"] for row in dns_evidence["observables"]],
                "relationship_ids": [], "title": "DNS indicator",
                "assessment": "Evidence-backed DNS activity.", "limitations": [],
                "recommended_follow_ups": [], "confidence": "moderate", "outcome": "suspected",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        }
        stored = admit_indicator_review(case, proposal)
        stale_case = dict(case)
        stale_case["evidence"] = [row for row in case["evidence"] if row["evidence_id"] != "EV-DNS-1"]

        rejected = admit_indicator_review(stale_case, indicator_review_proposal(stored))

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("unknown_evidence_id", rejected["rejection_codes"])


class IndicatorModelTests(unittest.TestCase):
    def test_schema_enumerates_visible_selectors_and_adapter_treats_case_as_untrusted(self):
        from romulus.config import Settings
        from romulus.reporting.indicator_review import build_indicator_case

        case = build_indicator_case(_state(), _items())
        proposal = _proposal(case)

        class Response:
            def raise_for_status(self): pass
            def iter_lines(self):
                import json
                content = json.dumps(proposal).replace('\\', '\\\\').replace('"', '\\"')
                yield ('{"message":{"content":"' + content +
                       '"},"done":true,"done_reason":"stop"}').encode()

        class Session:
            def __init__(self): self.payload = None
            def post(self, url, **kwargs): self.payload = kwargs["json"]; return Response()

        session = Session()
        with _ollama_module() as module:
            schema = module._indicator_review_schema(case)
            result = module.Ollama(Settings.from_env(), session).synthesize_indicator_review(case)

        indicator = schema["properties"]["strong_indicators"]["items"]["properties"]
        self.assertEqual(set(indicator["item_ids"]["items"]["enum"]), {"CL-DNS", "CL-WEB"})
        self.assertEqual(set(indicator["evidence_ids"]["items"]["enum"]), {
            "EV-DNS-1", "EV-DNS-2", "EV-WEB",
        })
        visible_observables = {
            row["observable_id"] for evidence in case["evidence"]
            for row in evidence["observables"]
        }
        self.assertEqual(set(indicator["observable_ids"]["items"]["enum"]), visible_observables)
        self.assertEqual(indicator["relationship_ids"]["items"]["enum"], ["COR-DNS"])
        self.assertNotIn("artifact", str(schema).lower())

        self.assertEqual(result["strong_indicators"][0]["item_ids"], ["CL-DNS"])
        self.assertFalse(session.payload["format"]["additionalProperties"])
        prompt = session.payload["messages"][1]["content"]
        self.assertIn("untrusted", prompt.lower())
        self.assertIn("strong_indicators", prompt)
        self.assertIn("likely_noise", prompt)
        self.assertIn("HUNT-INDICATORS", prompt)
        self.assertNotIn("ground_truth", prompt.lower())
        self.assertNotIn("answer-revealing", prompt.lower())


class IndicatorWorkflowTests(unittest.TestCase):
    def _engine(self, root, *, enabled=True):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store
        settings = replace(
            Settings.from_env(), home=root, data_dir=root / "data", logs_dir=root / "logs",
            reports_dir=root / "reports", max_runtime_seconds=1,
        )
        return HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=enabled)

    def _report_state(self):
        state = _state()
        state.update({
            "objective": "Hunt broadly", "status": "running", "outcome": "pending",
            "termination_reason": "runtime_budget", "summary": "", "tool_calls": 3,
            "depth": 1, "started_epoch": time.time() - 10, "source_errors": [],
            "tool_runs": [], "search_tasks": {}, "stage_history": [],
            "reasoning_history": [], "hypotheses": [], "search_artifacts": [],
            "candidate_leads": copy.deepcopy(_items()), "findings": [],
            "investigation_graph": {"version": 1, "nodes": [], "edges": [], "paths": [], "summary": {}},
        })
        for item in state["candidate_leads"]:
            item["candidate_id"] = item["item_id"]
        return state

    def test_finalization_synthesizes_once_after_discovery_runtime_expires(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            engine = self._engine(root)
            state = self._report_state()

            with _ollama_module() as module:
                with patch.object(module.Ollama, "synthesize_indicator_review",
                                  side_effect=lambda case: _proposal(case)) as model, \
                        patch("romulus.reporting.report.generate_report",
                              return_value=[root / "reports" / "report.docx", root / "reports" / "report.txt"]):
                    result = engine._report(state)

            self.assertEqual(model.call_count, 1)
            self.assertEqual(result["indicator_review"]["status"], "admitted")
            self.assertEqual(result["coverage"]["indicator_review"]["model_calls"], 1)
            self.assertEqual(result["coverage"]["indicator_review"]["model_result_status"], "ok")
            self.assertEqual(result["coverage"]["indicator_review"]["strong_indicators"], 1)
            self.assertEqual(len(result["report_paths"]), 2)
            reporting_runs = [row for row in result["tool_runs"]
                              if row.get("reasoning_stage") == "indicator_review_finalization"]
            self.assertEqual(len(reporting_runs), 1)
            self.assertEqual(reporting_runs[0]["result_status"], "ok")

    def test_model_failure_records_error_and_falls_back_without_blocking_report(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            engine = self._engine(root)
            state = self._report_state()

            with _ollama_module() as module:
                with patch.object(module.Ollama, "synthesize_indicator_review",
                                  side_effect=RuntimeError("model unavailable")) as model, \
                        patch("romulus.reporting.report.generate_report",
                              return_value=[root / "reports" / "report.docx", root / "reports" / "report.txt"]):
                    result = engine._report(state)

            self.assertEqual(model.call_count, 1)
            self.assertEqual(result["indicator_review"]["status"], "fallback")
            self.assertEqual(result["coverage"]["indicator_review"]["model_calls"], 1)
            self.assertEqual(result["coverage"]["indicator_review"]["model_result_status"], "error")
            self.assertIn("unavailable", result["indicator_review"]["reason"].lower())
            self.assertEqual(len(result["report_paths"]), 2)
            reporting_runs = [row for row in result["tool_runs"]
                              if row.get("reasoning_stage") == "indicator_review_finalization"]
            self.assertEqual(reporting_runs[0]["result_status"], "error")

    def test_disabled_model_uses_fallback_without_finalization_call(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            engine = self._engine(root, enabled=False)
            state = self._report_state()

            with _ollama_module() as module:
                with patch.object(module.Ollama, "synthesize_indicator_review") as model, \
                        patch("romulus.reporting.report.generate_report",
                              return_value=[root / "reports" / "report.docx", root / "reports" / "report.txt"]):
                    result = engine._report(state)

            model.assert_not_called()
            self.assertEqual(result["indicator_review"]["status"], "fallback")
            self.assertEqual(result["coverage"]["indicator_review"]["model_calls"], 0)
            self.assertEqual(result["coverage"]["indicator_review"]["model_result_status"], "not_attempted")


if __name__ == "__main__":
    unittest.main()
