import copy
import unittest


class CapabilityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {
                "id": "CAP-1",
                "title": "Netcat shell capability",
                "record_type": "source_capability_reference",
                "source_metadata": {"executable": "nc", "function": "shell"},
                "source_refs": ["GTFOBINS"],
                "source_url": "https://example.invalid/nc",
                "attack_techniques": ["T1059"],
            },
            {
                "id": "CAP-2",
                "title": "Netcat transfer capability",
                "record_type": "source_capability_reference",
                "source_metadata": {"executable": "nc", "function": "file-transfer"},
                "source_refs": ["GTFOBINS"],
                "source_url": "https://example.invalid/nc-transfer",
                "attack_techniques": ["T1105"],
            },
        ]

    def test_index_uses_exact_normalized_executable_names(self):
        from romulus.intelligence.reference_intelligence import compile_capability_index

        index = compile_capability_index(self.records)

        self.assertEqual([row["id"] for row in index["nc"]], ["CAP-1", "CAP-2"])
        self.assertNotIn("ncat", index)

    def test_context_is_evidence_attributed_bounded_and_score_neutral(self):
        from romulus.intelligence.reference_intelligence import (
            attach_capability_context,
            compile_capability_index,
        )

        candidate = {
            "candidate_id": "C-1",
            "priority_score": 81,
            "disposition": "corroborated",
            "customer_visible": True,
            "evidence_ids": ["E-1"],
        }
        evidence = [
            {"evidence_id": "E-1", "raw": {"process": {"executable": "/usr/bin/nc"}}},
            {"evidence_id": "E-2", "raw": {"process": {"name": "ncat"}}},
        ]
        original = copy.deepcopy(candidate)

        enriched = attach_capability_context(
            [candidate], evidence, compile_capability_index(self.records), limit=1
        )[0]

        self.assertEqual(enriched["priority_score"], original["priority_score"])
        self.assertEqual(enriched["disposition"], original["disposition"])
        self.assertEqual(enriched["customer_visible"], original["customer_visible"])
        self.assertEqual(len(enriched["capability_context"]), 1)
        self.assertEqual(enriched["capability_context"][0]["evidence_ids"], ["E-1"])
        self.assertEqual(enriched["capability_context"][0]["reference_id"], "CAP-1")
        self.assertNotIn("capability_context", candidate)


class AttackReferenceTests(unittest.TestCase):
    def test_exact_techniques_are_first_and_output_is_bounded(self):
        from romulus.intelligence.attack_catalog import bounded_attack_context

        rows = bounded_attack_context(
            "investigate suspicious PowerShell execution",
            ["T1059.001", "T1105", "T1059.001"],
            limit=3,
        )

        self.assertLessEqual(len(rows), 3)
        self.assertEqual([row["technique_id"] for row in rows[:2]], ["T1059.001", "T1105"])
        self.assertTrue(all(set(row) <= {
            "technique_id", "name", "url", "tactic", "tactics", "platforms",
            "is_subtechnique", "detection_strategies", "data_components", "mutable_elements",
        } for row in rows))


if __name__ == "__main__":
    unittest.main()
