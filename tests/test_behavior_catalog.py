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
