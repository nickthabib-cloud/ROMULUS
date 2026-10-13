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


class CandidateRelationshipTests(unittest.TestCase):
    caveat = "Temporal or entity association is an investigative lead, not causation."

    @staticmethod
    def _candidate(identifier, group, evidence_id, score=50):
        return {
            "candidate_id": identifier,
            "kind": "behavior",
            "analytic_id": f"AN-{identifier}",
            "corroboration_group": group,
            "analytic_source": "aggregate",
            "priority_score": score,
            "priority_tier": "medium",
            "disposition": "observed",
            "customer_visible": False,
            "evidence_ids": [evidence_id],
            "assets": ["shared-label"],
            "score_reasons": ["base score"],
            "follow_ups": [],
            "finding_ids": [],
        }

    @staticmethod
    def _event(identifier, observed_at, ip, *, role="source"):
        return {
            "evidence_id": identifier,
            "source": "synthetic",
            "observed_at": observed_at,
            "asset": "shared-label",
            "raw": {role: {"ip": ip}},
        }

    def test_distinct_groups_share_typed_evidence_at_window_boundary(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate("CL-A", "GROUP-A", "EV-A", 50),
            self._candidate("CL-B", "GROUP-B", "EV-B", 60),
        ]
        evidence = [
            self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
            self._event("EV-B", "2026-06-01T12:30:00Z", "10.55.0.8", role="host"),
        ]

        related = relate_candidates(candidates, evidence)

        by_id = {item["candidate_id"]: item for item in related}
        self.assertEqual(by_id["CL-A"]["priority_score"], 60)
        self.assertEqual(by_id["CL-B"]["priority_score"], 70)
        self.assertEqual(
            by_id["CL-A"]["related_candidates"],
            [{
                "candidate_id": "CL-B",
                "shared_entity_type": "ip",
                "shared_entity": "10.55.0.8",
                "evidence_ids": ["EV-A", "EV-B"],
                "time_delta_seconds": 1800,
                "confidence": "moderate",
                "caveat": self.caveat,
            }],
        )
        self.assertEqual(by_id["CL-B"]["related_candidates"][0]["candidate_id"], "CL-A")
        self.assertIn("GROUP-B", " ".join(by_id["CL-A"]["corroboration_reasons"]))
        self.assertTrue(by_id["CL-B"]["customer_visible"])
        self.assertEqual(by_id["CL-B"]["disposition"], "corroborated")

    def test_relationship_is_input_order_stable(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate("CL-A", "GROUP-A", "EV-A", 50),
            self._candidate("CL-B", "GROUP-B", "EV-B", 60),
        ]
        evidence = [
            self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
            self._event("EV-B", "2026-06-01T12:10:00Z", "10.55.0.8", role="destination"),
        ]

        self.assertEqual(
            relate_candidates(candidates, evidence),
            relate_candidates(list(reversed(candidates)), list(reversed(evidence))),
        )

    def test_just_outside_window_does_not_relate(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate("CL-A", "GROUP-A", "EV-A"),
            self._candidate("CL-B", "GROUP-B", "EV-B"),
        ]
        evidence = [
            self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
            self._event("EV-B", "2026-06-01T12:30:01Z", "10.55.0.8"),
        ]

        related = relate_candidates(candidates, evidence)

        self.assertTrue(all(item["related_candidates"] == [] for item in related))
        self.assertEqual({item["priority_score"] for item in related}, {50})

    def test_same_group_missing_time_and_asset_only_overlap_do_not_relate(self):
        from romulus.investigation.candidate_triage import relate_candidates

        cases = [
            (
                [self._candidate("CL-A", "SAME", "EV-A"), self._candidate("CL-B", "SAME", "EV-B")],
                [self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
                 self._event("EV-B", "2026-06-01T12:05:00Z", "10.55.0.8")],
            ),
            (
                [self._candidate("CL-A", "GROUP-A", "EV-A"), self._candidate("CL-B", "GROUP-B", "EV-B")],
                [self._event("EV-A", "", "10.55.0.8"),
                 self._event("EV-B", "2026-06-01T12:05:00Z", "10.55.0.8")],
            ),
            (
                [self._candidate("CL-A", "GROUP-A", "EV-A"), self._candidate("CL-B", "GROUP-B", "EV-B")],
                [self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
                 self._event("EV-B", "2026-06-01T12:05:00Z", "10.55.0.9")],
            ),
        ]

        for candidates, evidence in cases:
            with self.subTest(case=candidates[0]["corroboration_group"]):
                related = relate_candidates(candidates, evidence)
                self.assertTrue(all(item["related_candidates"] == [] for item in related))
                self.assertTrue(all(item["priority_score"] == 50 for item in related))

    def test_bonus_is_capped_and_recalculation_is_idempotent(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate(f"CL-{suffix}", f"GROUP-{suffix}", f"EV-{suffix}", 40)
            for suffix in ("A", "B", "C", "D")
        ]
        evidence = [
            self._event(f"EV-{suffix}", f"2026-06-01T12:0{index}:00Z", "10.55.0.8")
            for index, suffix in enumerate(("A", "B", "C", "D"))
        ]

        related = relate_candidates(candidates, evidence)
        recalculated = relate_candidates(related, evidence)

        self.assertTrue(all(item["corroboration_bonus"] == 20 for item in related))
        self.assertTrue(all(item["priority_score"] == 60 for item in related))
        self.assertEqual(recalculated, related)


if __name__ == "__main__":
    unittest.main()
