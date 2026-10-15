import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class IntelligenceAssetAuditTests(unittest.TestCase):
    def test_asset_registry_assigns_owner_consumer_and_class(self):
        registry_path = ROOT / "romulus" / "intelligence" / "intelligence_assets.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        allowed = {
            "authoritative_input",
            "generated_runtime",
            "runtime_configuration",
            "operator_document",
            "historical_design",
        }
        self.assertGreater(len(registry["assets"]), 10)
        for asset in registry["assets"]:
            self.assertIn(asset["class"], allowed, asset["path"])
            self.assertTrue(asset["owner"], asset["path"])
            self.assertTrue(asset["consumers"], asset["path"])

    def test_generated_pack_contains_capabilities_without_attack_copy(self):
        from romulus.intelligence.behavior_packs import load_behavior_packs

        packs = load_behavior_packs()
        self.assertIn("capabilities", packs)
        self.assertNotIn("references", packs)
        records = packs["capabilities"]["records"]
        self.assertEqual(len(records), 1216)
        self.assertEqual(
            {row["record_type"] for row in records},
            {"source_capability_reference"},
        )
        self.assertNotIn("attack_analytic_index", packs["capabilities"])
        self.assertEqual(packs["manifest"]["pack_counts"]["capabilities"], 1216)

    def test_retired_duplicate_assets_are_absent(self):
        self.assertFalse((ROOT / "docs" / "research" / "common-indicator-index.csv").exists())
        self.assertFalse(
            (ROOT / "romulus" / "intelligence" / "behavior_packs" / "references.json").exists()
        )

    def test_asset_audit_reconciles_authoritative_and_generated_counts(self):
        from scripts.audit_intelligence_assets import audit_assets

        result = audit_assets(ROOT)
        self.assertEqual(result["status"], "ok", result.get("errors"))
        self.assertEqual(result["counts"]["curated_behaviors"], 902)
        self.assertEqual(result["counts"]["capability_references"], 1216)
        self.assertEqual(result["counts"]["attack_techniques"], 697)
        self.assertEqual(result["errors"], [])

    def test_asset_audit_rejects_retired_file_reference(self):
        from scripts.audit_intelligence_assets import audit_assets

        scratch = ROOT / ".codex-tmp"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            (root / "romulus" / "intelligence").mkdir(parents=True)
            registry = {
                "schema_version": "1.0.0",
                "assets": [
                    {
                        "path": "docs/research/common-indicator-index.csv",
                        "class": "operator_document",
                        "owner": "test",
                        "consumers": ["test"],
                    }
                ],
            }
            (root / "romulus" / "intelligence" / "intelligence_assets.json").write_text(
                json.dumps(registry), encoding="utf-8"
            )
            result = audit_assets(root)
            self.assertEqual(result["status"], "error")
            self.assertTrue(any("retired asset" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
