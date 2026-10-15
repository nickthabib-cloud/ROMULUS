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
        "hunt_id": "HUNT-NARRATIVE",
        "candidate_leads": [
            {
                "candidate_id": "CL-A", "classification": "suspicious",
                "investigation_status": "resolved", "title": "Unusual script execution",
                "description": "A script interpreter launched an encoded command on app-01.",
                "classification_reason": "A reviewed execution behavior matched.",
                "evidence_ids": ["EV-A"], "finding_ids": [],
                "related_candidates": [{
                    "candidate_id": "CL-B", "shared_entity_type": "host",
                    "shared_entity": "app-01", "evidence_ids": ["EV-A", "EV-B"],
                    "time_delta_seconds": 120, "confidence": "moderate",
                    "caveat": "Shared entity and time proximity do not prove causality.",
                }],
            },
            {
                "candidate_id": "CL-B", "classification": "suspicious",
                "investigation_status": "follow_up_exhausted", "title": "Outbound callback pattern",
                "description": "app-01 connected to 198.51.100.24 shortly after execution.",
                "classification_reason": "A reviewed callback behavior matched.",
                "evidence_ids": ["EV-B"], "finding_ids": [],
                "related_candidates": [{
                    "candidate_id": "CL-A", "shared_entity_type": "host",
                    "shared_entity": "app-01", "evidence_ids": ["EV-B", "EV-A"],
                    "time_delta_seconds": 120, "confidence": "moderate",
                    "caveat": "Shared entity and time proximity do not prove causality.",
                }],
            },
            {
                "candidate_id": "CL-C", "classification": "malicious",
                "investigation_status": "new", "title": "Current exact indicator match",
                "description": "A current trusted domain indicator other.example was observed.",
                "classification_reason": "The strict trusted-indicator gate passed.",
                "kind": "trusted_indicator", "indicator_confidence": 95,
                "indicator_id": "IOC-NARRATIVE-C",
                "indicator_source": "customer incident response", "indicator_type": "domain",
                "indicator_value": "other.example", "indicator_match_type": "exact",
                "indicator_current_at_match": True,
                "indicator_catalog_version": "1.0.0",
                "indicator_created_at": "2026-01-01T00:00:00Z",
                "indicator_expires_at": "2027-01-01T00:00:00Z",
                "indicator_matched_at": "2026-02-03T07:00:00Z",
                "evidence_ids": ["EV-C"], "finding_ids": [],
            },
            {
                "candidate_id": "CL-NOISE", "classification": "anomalous",
                "investigation_status": "new", "title": "Weak anomaly",
                "description": "Not reportable.", "evidence_ids": ["EV-NOISE"],
                "finding_ids": [],
            },
        ],
        "findings": [],
        "host": [
            {"evidence_id": "EV-A", "source": "elasticsearch",
             "observed_at": "2026-02-03T04:05:00Z", "asset": "app-01",
             "observation": "Encoded script execution was observed."},
            {"evidence_id": "EV-C", "source": "elasticsearch",
             "observed_at": "2026-02-03T07:00:00Z", "asset": "desk-02",
             "observation": "Exact lookup of other.example was observed."},
            {"evidence_id": "EV-NOISE", "source": "elasticsearch",
             "observed_at": "2026-02-03T08:00:00Z", "asset": "desk-03",
             "observation": "Noise that must not enter the narrative case."},
        ],
        "network": [{
            "evidence_id": "EV-B", "source": "arkime",
            "observed_at": "2026-02-03T04:07:00Z", "asset": "app-01",
            "observation": "app-01 connected to 198.51.100.24 over TCP.",
        }],
        "coverage": {"scheduler_gaps": [{"reason": "packet payload unavailable"}]},
        "investigation_graph": {"paths": []},
    }


def _valid_proposal(case):
    relation_id = case["relationships"][0]["relationship_id"]
    return {
        "no_coherent_narrative": False,
        "clusters": [{
            "item_ids": ["CL-A", "CL-B"],
            "relationship_ids": [relation_id],
            "evidence_ids": ["EV-A", "EV-B"],
            "possible_sequence": ["CL-A", "CL-B"],
            "confidence": "moderate",
        }],
        "unconnected_item_ids": ["CL-C"],
    }


def _empty_indicator_proposal(case):
    return {
        "strong_indicators": [], "supporting_context": [], "likely_noise": [],
        "possible_activity_narrative": {
            "item_ids": [], "relationship_ids": [], "summary": "", "limitations": [],
        },
        "recommended_follow_ups": [],
    }


class NarrativeAdmissionTests(unittest.TestCase):
    def test_case_contains_only_reportable_owned_bounded_facts_and_stable_relationships(self):
        from romulus.investigation.narrative import build_narrative_case
        from romulus.reporting.report_items import build_report_items

        state = _state()
        first = build_narrative_case(state, build_report_items(state))
        second = build_narrative_case(state, build_report_items(state))

        self.assertEqual([row["item_id"] for row in first["items"]], ["CL-A", "CL-B", "CL-C"])
        self.assertEqual({row["evidence_id"] for row in first["evidence"]}, {"EV-A", "EV-B", "EV-C"})
        self.assertNotIn("EV-NOISE", str(first))
        self.assertEqual(first["relationships"], second["relationships"])
        self.assertEqual(len(first["relationships"]), 1)
        self.assertRegex(first["relationships"][0]["relationship_id"], r"^REL-[A-F0-9]{16}$")

        oversized = copy.deepcopy(state)
        oversized["candidate_leads"] = []
        oversized["host"] = []
        for number in range(60):
            oversized["candidate_leads"].append({
                "candidate_id": f"CL-{number:02d}", "classification": "suspicious",
                "investigation_status": "new", "title": f"Behavior {number}",
                "evidence_ids": [f"EV-{number:02d}"], "finding_ids": [],
            })
            oversized["host"].append({"evidence_id": f"EV-{number:02d}", "observation": "fact"})
        bounded = build_narrative_case(oversized, build_report_items(oversized))
        self.assertEqual(len(bounded["items"]), 12)
        self.assertLessEqual(len(bounded["evidence"]), 48)

    def test_valid_cluster_is_admitted_and_unrelated_item_remains_unconnected(self):
        from romulus.investigation.narrative import admit_activity_narrative, build_narrative_case
        from romulus.reporting.report_items import build_report_items

        case = build_narrative_case(_state(), build_report_items(_state()))
        admitted = admit_activity_narrative(case, _valid_proposal(case))

        self.assertEqual(admitted["status"], "admitted")
        self.assertFalse(admitted["no_coherent_narrative"])
        self.assertEqual(admitted["clusters"][0]["item_ids"], ["CL-A", "CL-B"])
        self.assertEqual(admitted["unconnected_item_ids"], ["CL-C"])
        self.assertIn("Unusual script execution", admitted["clusters"][0]["narrative"])
        self.assertIn("Outbound callback pattern", admitted["clusters"][0]["narrative"])
        self.assertNotIn("classification", str(admitted).lower())

    def test_no_coherent_result_normalizes_every_item_to_unconnected(self):
        from romulus.investigation.narrative import admit_activity_narrative, build_narrative_case
        from romulus.reporting.report_items import build_report_items

        case = build_narrative_case(_state(), build_report_items(_state()))
        admitted = admit_activity_narrative(case, {
            "no_coherent_narrative": True, "clusters": [],
            "unconnected_item_ids": [],
        })

        self.assertTrue(admitted["no_coherent_narrative"])
        self.assertEqual(admitted["unconnected_item_ids"], ["CL-A", "CL-B", "CL-C"])

    def test_invalid_identifiers_citations_placement_connectivity_and_invented_facts_fail_closed(self):
        from romulus.investigation.narrative import admit_activity_narrative, build_narrative_case
        from romulus.reporting.report_items import build_report_items

        case = build_narrative_case(_state(), build_report_items(_state()))
        mutations = {}
        for label in (
            "unknown item", "unknown evidence", "unknown relationship", "invisible citation",
            "repeated placement", "disconnected cluster", "invented prose",
            "classification mutation",
        ):
            mutations[label] = _valid_proposal(case)
        mutations["unknown item"]["clusters"][0]["item_ids"][0] = "CL-UNKNOWN"
        mutations["unknown evidence"]["clusters"][0]["evidence_ids"].append("EV-UNKNOWN")
        mutations["unknown relationship"]["clusters"][0]["relationship_ids"] = ["REL-UNKNOWN"]
        mutations["invisible citation"]["clusters"][0]["evidence_ids"].append("EV-C")
        mutations["repeated placement"]["unconnected_item_ids"].append("CL-A")
        mutations["disconnected cluster"]["clusters"][0]["item_ids"].append("CL-C")
        mutations["disconnected cluster"]["clusters"][0]["evidence_ids"].append("EV-C")
        mutations["disconnected cluster"]["clusters"][0]["possible_sequence"].append("CL-C")
        mutations["invented prose"]["clusters"][0]["narrative"] = (
            "Mimikatz harvested administrator credentials."
        )
        mutations["classification mutation"]["clusters"][0]["classification"] = "malicious"

        for label, proposal in mutations.items():
            with self.subTest(label=label):
                rejected = admit_activity_narrative(case, proposal)
                self.assertEqual(rejected["status"], "rejected")
                self.assertTrue(rejected["no_coherent_narrative"])
                self.assertEqual(rejected["clusters"], [])
                self.assertEqual(rejected["unconnected_item_ids"], ["CL-A", "CL-B", "CL-C"])
                self.assertLessEqual(len(rejected["reason"]), 240)


class NarrativeModelContractTests(unittest.TestCase):
    def test_schema_enumerates_only_visible_ids_and_carries_no_authoritative_fields(self):
        from romulus.investigation.narrative import build_narrative_case
        from romulus.reporting.report_items import build_report_items

        case = build_narrative_case(_state(), build_report_items(_state()))
        with _ollama_module() as module:
            schema = module._activity_narrative_schema(case)
        serialized = str(schema).lower()
        cluster = schema["properties"]["clusters"]["items"]["properties"]

        self.assertEqual(set(cluster["item_ids"]["items"]["enum"]), {"CL-A", "CL-B", "CL-C"})
        self.assertEqual(set(cluster["evidence_ids"]["items"]["enum"]), {"EV-A", "EV-B", "EV-C"})
        self.assertEqual(cluster["relationship_ids"]["items"]["enum"], [case["relationships"][0]["relationship_id"]])
        for forbidden in ("classification", "entity", "finding", "query", "tool_action", "tool action"):
            self.assertNotIn(forbidden, serialized)
        self.assertNotIn("narrative", cluster)
        self.assertNotIn("alternate_explanations", cluster)
        self.assertNotIn("missing_evidence", cluster)
        self.assertNotIn("limitations", schema["properties"])

    def test_adapter_uses_strict_schema_and_untrusted_case_prompt(self):
        from romulus.config import Settings
        from romulus.investigation.narrative import build_narrative_case
        from romulus.reporting.report_items import build_report_items

        case = build_narrative_case(_state(), build_report_items(_state()))

        class Response:
            def raise_for_status(self): pass
            def iter_lines(self):
                yield (b'{"message":{"content":"{\\"no_coherent_narrative\\":true,'
                       b'\\"clusters\\":[],\\"unconnected_item_ids\\":[]}"},'
                       b'"done":true,"done_reason":"stop"}')

        class Session:
            def __init__(self): self.payload = None
            def post(self, url, **kwargs): self.payload = kwargs["json"]; return Response()

        session = Session()
        with _ollama_module() as module:
            result = module.Ollama(Settings.from_env(), session).synthesize_activity_narrative(case)

        self.assertTrue(result["no_coherent_narrative"])
        self.assertFalse(session.payload["format"]["additionalProperties"])
        prompt = session.payload["messages"][1]["content"]
        self.assertIn("untrusted", prompt.lower())
        self.assertIn("no coherent narrative", prompt.lower())
        self.assertIn("HUNT-NARRATIVE", prompt)


class NarrativeWorkflowTests(unittest.TestCase):
    def _engine(self, root, *, enabled=True, max_tool_calls=20):
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store
        settings = replace(
            Settings.from_env(), home=root, data_dir=root / "data", logs_dir=root / "logs",
            reports_dir=root / "reports", max_tool_calls=max_tool_calls,
        )
        return HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=enabled)

    def _report_state(self):
        state = _state()
        state.update({
            "objective": "Hunt broadly", "status": "running", "outcome": "pending",
            "termination_reason": "lead_queue_exhausted", "summary": "", "tool_calls": 0,
            "depth": 1, "started_epoch": time.time(), "source_errors": [], "tool_runs": [],
            "search_tasks": {}, "stage_history": [], "reasoning_history": [],
            "correlations": [], "hypotheses": [], "search_artifacts": [],
        })
        state["coverage"].update({"host": "available", "network": "available"})
        return state

    def test_report_calls_model_once_admits_output_and_does_not_mutate_authoritative_records(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory); engine = self._engine(root)
            state = self._report_state()
            candidates = copy.deepcopy(state["candidate_leads"])
            findings = copy.deepcopy(state["findings"])
            graph = copy.deepcopy(state["investigation_graph"])

            def proposal(case): return _valid_proposal(case)

            with _ollama_module() as module:
                with patch.object(module.Ollama, "synthesize_activity_narrative", side_effect=proposal) as model, \
                        patch.object(module.Ollama, "synthesize_indicator_review", side_effect=_empty_indicator_proposal), \
                        patch("romulus.reporting.report.generate_report", return_value=[root / "report.docx", root / "report.txt"]):
                    result = engine._report(state)

            self.assertEqual(model.call_count, 1)
            self.assertEqual(result["activity_narrative"]["status"], "admitted")
            self.assertEqual(result["coverage"]["activity_narrative"]["model_calls"], 1)
            self.assertEqual(result["candidate_leads"], candidates)
            self.assertEqual(result["findings"], findings)
            self.assertEqual(result["investigation_graph"], graph)
            self.assertEqual(len(result["report_paths"]), 2)
            self.assertEqual(result["outcome"], "evidence_supported_lead")
            self.assertIn("reportable behavior", result["summary"])

    def test_candidate_free_disabled_and_exhausted_hunts_use_fallback_without_model_call(self):
        cases = (("candidate free", True, 20, False), ("disabled", False, 20, True),
                 ("exhausted", True, 1, True))
        for label, enabled, limit, with_candidate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                root = Path(directory); engine = self._engine(root, enabled=enabled, max_tool_calls=limit)
                state = self._report_state()
                if not with_candidate:
                    state["candidate_leads"] = []; state["host"] = []; state["network"] = []
                if label == "exhausted": state["tool_calls"] = limit
                with _ollama_module() as module:
                    with patch.object(module.Ollama, "synthesize_activity_narrative") as model, \
                            patch.object(module.Ollama, "synthesize_indicator_review", side_effect=_empty_indicator_proposal), \
                            patch("romulus.reporting.report.generate_report", return_value=[root / "report.docx", root / "report.txt"]):
                        result = engine._report(state)
                model.assert_not_called()
                self.assertTrue(result["activity_narrative"]["no_coherent_narrative"])
                self.assertEqual(result["coverage"]["activity_narrative"]["model_calls"], 0)

    def test_invalid_or_failed_model_output_cannot_suppress_report_items(self):
        invalid = {
            "no_coherent_narrative": False,
            "clusters": [{"item_ids": ["CL-UNKNOWN"], "relationship_ids": [],
                "evidence_ids": [], "possible_sequence": ["CL-UNKNOWN"],
                "confidence": "high"}],
            "unconnected_item_ids": [],
        }
        for label, effect in (("invalid", lambda case: invalid), ("failure", RuntimeError("model unavailable"))):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                root = Path(directory); engine = self._engine(root)
                state = self._report_state(); original = copy.deepcopy(state["candidate_leads"])
                with _ollama_module() as module:
                    call = patch.object(module.Ollama, "synthesize_activity_narrative",
                        side_effect=effect if isinstance(effect, Exception) else effect)
                    with call, patch.object(module.Ollama, "synthesize_indicator_review", side_effect=_empty_indicator_proposal), \
                            patch("romulus.reporting.report.generate_report", return_value=[root / "report.docx", root / "report.txt"]):
                        result = engine._report(state)
                self.assertTrue(result["activity_narrative"]["no_coherent_narrative"])
                self.assertEqual(result["candidate_leads"], original)
                self.assertEqual(len(result["report_paths"]), 2)


if __name__ == "__main__":
    unittest.main()
