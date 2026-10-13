import unittest


class CandidateNetworkPivotTests(unittest.TestCase):
    def test_candidate_network_spec_uses_only_primary_ip_with_behavior(self):
        from romulus.investigation.search_planner import candidate_network_spec, compile_arkime, compile_tshark

        spec = candidate_network_spec(
            {
                "candidate_id": "CL-SCAN",
                "ips": ["10.40.5.9", "10.40.8.20", "not-an-ip"],
                "hostnames": ["ignored.example.test"],
            },
            {"ports": [], "protocols": ["tcp", "udp"]},
            require_entity=True,
        )

        self.assertEqual(spec["ips"], ["10.40.5.9"])
        self.assertEqual(spec["hostnames"], [])
        arkime = compile_arkime(spec)
        tshark, _ = compile_tshark(spec)
        for expression in (arkime, tshark):
            self.assertIn("10.40.5.9", expression)
            self.assertNotIn("10.40.8.20", expression)
            self.assertNotIn("ignored.example.test", expression)
        self.assertIn("protocols == tcp", arkime)
        self.assertIn("protocols == udp", arkime)
        self.assertIn("tcp", tshark)
        self.assertIn("udp", tshark)

    def test_candidate_network_spec_uses_safe_hostname_only_without_ip(self):
        from romulus.investigation.search_planner import candidate_network_spec, compile_arkime

        spec = candidate_network_spec(
            {
                "candidate_id": "CL-DNS",
                "ips": ["malformed-ip"],
                "hostnames": ["telemetry.example.test", "ignored.example.test"],
            },
            {"ports": [53], "protocols": ["dns"]},
            require_entity=True,
        )

        self.assertEqual(spec["ips"], [])
        self.assertEqual(spec["hostnames"], ["telemetry.example.test"])
        expression = compile_arkime(spec)
        self.assertIn("dns.host == *telemetry.example.test*", expression)
        self.assertNotIn("ignored.example.test", expression)
        self.assertIn("protocols == dns", expression)

    def test_candidate_network_spec_rejects_missing_safe_entity(self):
        from romulus.investigation.search_planner import candidate_network_spec

        with self.assertRaisesRegex(ValueError, "candidate network pivot requires"):
            candidate_network_spec(
                {"candidate_id": "CL-EMPTY", "ips": ["999.1.1.1"], "hostnames": ["bad host value"]},
                {"ports": [443], "protocols": ["tls"]},
                require_entity=True,
            )

    def test_workflow_candidate_helpers_include_primary_entity(self):
        from romulus.investigation.workflow import _lead_network_expression, _lead_pcap_filter

        lead = {
            "candidate_id": "CL-SCAN",
            "technique_id": "T1046",
            "ips": ["10.40.5.9", "10.40.8.20"],
            "hostnames": [],
        }

        arkime = _lead_network_expression(lead)
        tshark = _lead_pcap_filter(lead)
        self.assertIn("10.40.5.9", arkime)
        self.assertIn("10.40.5.9", tshark)
        self.assertNotIn("10.40.8.20", arkime)
        self.assertNotIn("10.40.8.20", tshark)
        self.assertIn("protocols == tcp", arkime)
        self.assertIn("protocols == udp", arkime)

    def test_non_candidate_coverage_lead_may_remain_behavior_only(self):
        from romulus.investigation.workflow import _lead_network_expression, _lead_pcap_filter

        arkime = _lead_network_expression({"technique_id": "T1046"})
        tshark = _lead_pcap_filter({"technique_id": "T1046"})

        self.assertEqual(arkime, "(protocols == tcp || protocols == udp)")
        self.assertEqual(tshark, "((tcp || udp))")


if __name__ == "__main__":
    unittest.main()
