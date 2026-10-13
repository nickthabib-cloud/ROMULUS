import copy
import json
import unittest


def _state():
    return {
        "hunt_id": "HUNT-CASEFILE",
        "objective": "Hunt for evidence-backed suspicious behavior in the bounded mission window.",
        "mission_mode": "undirected",
        "coverage": {
            "time_scope": "2022-01-24T03:00:00Z through 2022-01-24T05:00:00Z",
            "host": "available; 120 events examined",
            "network": "available; 80 sessions examined",
            "scheduler_gaps": [{
                "phase": "investigation",
                "reason": "source_unavailable",
                "source_family": "dns",
                "query_spec": {"password": "COVERAGE-SECRET"},
            }],
            "hypothesis_coverage": {
                "rows": [{
                    "hypothesis_id": "H-OPEN",
                    "closed": False,
                    "unresolved_task_ids": ["ST-OPEN"],
                }],
                "candidate_rows": [{
                    "candidate_id": "CL-HIGH",
                    "closed": False,
                    "unfinished_follow_up_ids": ["FU-HIGH"],
                    "unresolved_task_ids": ["ST-OPEN"],
                }],
            },
        },
        "source_health": {"host": True, "network": True, "dns": False},
        "source_errors": [{"source": "dns", "error_kind": "Unavailable", "detail": "bounded failure"}],
        "candidate_leads": [
            {
                "candidate_id": "CL-LOW",
                "kind": "behavior",
                "title": "Recent low-priority observation",
                "priority_tier": "low",
                "priority_score": 10,
                "disposition": "observed",
                "evidence_ids": ["EV-RECENT"],
                "follow_ups": [],
            },
            {
                "candidate_id": "CL-HIGH",
                "kind": "behavior",
                "title": "High-priority observed sequence",
                "priority_tier": "high",
                "priority_score": 91,
                "disposition": "corroborated",
                "evidence_ids": ["EV-ANCHOR"],
                "assets": ["web-01"],
                "attack_techniques": ["T1059"],
                "benign_explanations": ["Authorized maintenance"],
                "follow_ups": [{
                    "follow_up_id": "FU-HIGH",
                    "intent": "Check activity immediately before and after the anchor.",
                    "status": "pending",
                    "history": [],
                }],
            },
        ],
        "hypotheses": [{
            "hypothesis_id": "H-OPEN",
            "candidate_id": "CL-HIGH",
            "title": "Observed sequence may represent command execution",
            "technique_id": "T1059",
            "status": "inconclusive",
            "candidate_evidence_ids": ["EV-ANCHOR"],
            "expected_host": ["A process sequence adjacent to the anchor"],
            "expected_network": ["A related outbound session"],
            "benign_explanations": ["Authorized maintenance"],
        }],
        "host": [
            {
                "evidence_id": "EV-ANCHOR",
                "source": "elasticsearch",
                "asset": "web-01",
                "observed_at": "2022-01-24T03:58:20Z",
                "observation": "Observed command execution artifact",
                "raw": {
                    "process.name": "php",
                    "process.command_line": "php -r harmless-test",
                    "password": "RAW-SECRET",
                },
                "provenance": {"search_id": "ST-DONE", "query": "PROVENANCE-SECRET"},
            },
            {
                "evidence_id": "EV-RECENT",
                "source": "elasticsearch",
                "asset": "user-01",
                "observed_at": "2022-01-24T04:38:00Z",
                "observation": "Recent but low-priority artifact",
            },
        ],
        "network": [{
            "evidence_id": "EV-NET",
            "source": "arkime",
            "asset": "web-01",
            "observed_at": "2022-01-24T03:58:30Z",
            "observation": "Network session adjacent to the host anchor",
            "raw": {"source.ip": "192.0.2.10", "destination.ip": "192.0.2.20"},
        }],
        "search_tasks": {
            "ST-DONE": {
                "task_id": "ST-DONE",
                "source": "elasticsearch",
                "source_family": "host",
                "phase": "investigation",
                "intent": "Validate the observed process sequence",
                "candidate_ids": ["CL-HIGH"],
                "follow_up_ids": ["FU-HIGH"],
                "hypothesis_ids": ["H-OPEN"],
                "status": "partial",
                "query_spec": {"query": {"term": {"password": "QUERY-SECRET"}}},
            },
            "ST-OPEN": {
                "task_id": "ST-OPEN",
                "source": "arkime",
                "source_family": "network",
                "intent": "Unfinished pivot",
                "status": "queued",
                "query_spec": {"expression": "OPEN-QUERY-SECRET"},
            },
        },
        "search_outcomes": [{
            "task_id": "ST-DONE",
            "status": "partial",
            "returned_total": 5,
            "matched_total": 12,
            "total_relation": "gte",
            "capped": True,
            "timed_out": False,
            "shard_failures": 0,
            "incomplete": True,
            "error_kind": "ResultCap",
            "reason": "configured result cap reached",
            "evidence_ids": ["EV-ANCHOR"],
            "sampling": {
                "version": 1,
                "strategy": "rank_stratified",
                "requested_strata": 8,
                "covered_strata": 7,
            },
        }],
        "investigation_graph": {
            "version": 1,
            "paths": [{
                "path_id": "PATH-1",
                "finding_id": "F-1",
                "title": "Observed execution sequence",
                "confidence": "moderate",
                "steps": [{
                    "sequence": 1,
                    "activity_type": "process_execution",
                    "label": "Observed process on web-01",
                    "observed_at": "2022-01-24T03:58:20Z",
                    "evidence_ids": ["EV-ANCHOR"],
                    "entities": [{"entity_type": "host", "value": "web-01"}],
                }],
                "relationships": [{"from_sequence": 1, "to_sequence": 2, "relationship": "precedes"}],
                "gaps": ["No authentication event is visible."],
                "caveats": ["One step does not establish compromise."],
            }],
        },
        "progress_history": [
            {"stage": "analysis", "material_progress": True, "changed_ids": {"new_evidence": ["EV-ANCHOR"]}},
            {
                "stage": "reasoning",
                "material_progress": False,
                "signals": {"new_evidence": 0, "new_paths": 0},
                "changed_ids": {"new_evidence": []},
                "stagnant_cycles": 1,
                "private_note": "NOVELTY-SECRET",
            },
        ],
        "credentials": {"password": "TOP-LEVEL-SECRET"},
        "unrelated_working_state": "DO-NOT-EXPOSE",
    }


class CaseFileTests(unittest.TestCase):
    def test_evidence_budget_gives_every_frontier_candidate_an_anchor_before_extras(self):
        from romulus.investigation.casefile import build_case_file

        candidates = []
        evidence = []
        for candidate_index in range(8):
            evidence_ids = [
                f"EV-{candidate_index}-{evidence_index}" for evidence_index in range(6)
            ]
            candidates.append({
                "candidate_id": f"CL-{candidate_index}",
                "kind": "behavior",
                "corroboration_group": f"group-{candidate_index}",
                "priority_tier": "high",
                "priority_score": 88 - candidate_index,
                "disposition": "observed",
                "evidence_ids": evidence_ids,
                "follow_ups": [],
            })
            evidence.extend({
                "evidence_id": evidence_id,
                "source": "elasticsearch",
                "observed_at": f"2026-09-01T10:{candidate_index:02d}:00Z",
                "observation": "bounded synthetic record",
            } for evidence_id in evidence_ids)
        state = {
            "hunt_id": "HUNT-FAIR-ALLOCATION",
            "candidate_leads": candidates,
            "hypotheses": [],
            "host": evidence,
            "network": [],
        }

        case = build_case_file(state, candidate_limit=8, evidence_limit=24)

        self.assertEqual(len(case["candidates"]), 8)
        self.assertTrue(all(item["evidence_ids"] for item in case["candidates"]))
        self.assertEqual(len(case["evidence"]), 24)

    def test_hidden_relationship_has_no_visible_reason_or_score_claim(self):
        from romulus.investigation.casefile import build_case_file

        state = {
            "hunt_id": "HUNT-HIDDEN-RELATIONSHIP",
            "candidate_leads": [
                {
                    "candidate_id": "CL-A",
                    "kind": "behavior",
                    "corroboration_group": "group-a",
                    "priority_tier": "high",
                    "priority_score": 75,
                    "disposition": "corroborated",
                    "evidence_ids": ["EV-A"],
                    "score_reasons": ["base score", "evidence-backed corroboration contribution 10"],
                    "corroboration_reasons": ["LEAKED HIDDEN RELATIONSHIP"],
                    "related_candidates": [{
                        "candidate_id": "CL-B",
                        "shared_entity_type": "host",
                        "shared_entity": "srv-01",
                        "evidence_ids": ["EV-A", "EV-B"],
                        "time_delta_seconds": 60,
                        "confidence": "moderate",
                        "caveat": "Temporal association is not causation.",
                    }],
                    "follow_ups": [],
                },
                {
                    "candidate_id": "CL-B",
                    "kind": "behavior",
                    "corroboration_group": "group-b",
                    "priority_tier": "medium",
                    "priority_score": 50,
                    "disposition": "observed",
                    "evidence_ids": ["EV-B"],
                    "follow_ups": [],
                },
            ],
            "hypotheses": [],
            "host": [
                {"evidence_id": "EV-A", "source": "elasticsearch",
                 "observed_at": "2026-09-01T10:00:00Z", "observation": "first"},
                {"evidence_id": "EV-B", "source": "elasticsearch",
                 "observed_at": "2026-09-01T10:01:00Z", "observation": "second"},
            ],
            "network": [],
        }

        case = build_case_file(state, candidate_limit=1, evidence_limit=1)
        candidate = case["candidates"][0]

        self.assertEqual(candidate["candidate_id"], "CL-A")
        self.assertEqual(candidate["related_candidates"], [])
        self.assertEqual(candidate["corroboration_reasons"], [])
        self.assertFalse(any("corroboration" in reason for reason in candidate["score_reasons"]))

    def test_preferred_large_candidate_keeps_bounded_visible_ownership(self):
        from romulus.investigation.casefile import build_case_file, visible_case_ids

        evidence_ids = [f"EV-BULK-{index:02d}" for index in range(30)]
        state = {
            "hunt_id": "HUNT-BOUNDED",
            "objective": "Hunt for evidence-backed suspicious behavior.",
            "mission_mode": "undirected",
            "candidate_leads": [
                {
                    "candidate_id": "CL-ORDINARY",
                    "kind": "behavior",
                    "corroboration_group": "ordinary",
                    "priority_tier": "high",
                    "priority_score": 85,
                    "disposition": "observed",
                    "evidence_ids": ["EV-ORDINARY"],
                    "follow_ups": [],
                },
                {
                    "candidate_id": "CL-BULK",
                    "kind": "behavior",
                    "corroboration_group": "bulk",
                    "priority_tier": "medium",
                    "priority_score": 55,
                    "disposition": "observed",
                    "evidence_ids": list(reversed(evidence_ids)),
                    "follow_ups": [],
                },
            ],
            "hypotheses": [{
                "hypothesis_id": "H-BULK",
                "candidate_id": "CL-BULK",
                "basis_candidate_ids": ["CL-BULK"],
                "status": "untested",
                "candidate_evidence_ids": evidence_ids,
            }],
            "host": [
                {
                    "evidence_id": identifier,
                    "source": "elasticsearch",
                    "observed_at": f"2026-09-01T10:{index:02d}:00Z",
                    "observation": "bounded synthetic record",
                }
                for index, identifier in enumerate(evidence_ids)
            ] + [{
                "evidence_id": "EV-ORDINARY",
                "source": "elasticsearch",
                "observed_at": "2026-09-01T11:00:00Z",
                "observation": "ordinary record",
            }],
            "network": [],
        }

        case = build_case_file(state, candidate_limit=1, evidence_limit=24)
        candidate = case["candidates"][0]
        visible = visible_case_ids(case)

        self.assertEqual(candidate["candidate_id"], "CL-BULK")
        self.assertEqual(candidate["evidence_ids"], evidence_ids[:6])
        self.assertEqual(candidate["evidence_total"], 30)
        self.assertEqual(case["hypotheses"][0]["evidence_ids"], evidence_ids[:6])
        self.assertEqual(visible["candidate"], {"CL-BULK"})
        self.assertTrue(set(evidence_ids[:6]).issubset(visible["evidence"]))
        self.assertTrue(set(evidence_ids[6:]).isdisjoint(visible["evidence"]))

    def test_candidate_anchor_evidence_is_prioritized_and_state_is_unchanged(self):
        from romulus.investigation.casefile import build_case_file, visible_case_ids

        state = _state()
        original = copy.deepcopy(state)
        first = build_case_file(state, candidate_limit=1, evidence_limit=1)
        second = build_case_file(state, candidate_limit=1, evidence_limit=1)

        self.assertEqual(first, second)
        self.assertEqual(state, original)
        self.assertEqual([row["candidate_id"] for row in first["candidates"]], ["CL-HIGH"])
        self.assertEqual([row["evidence_id"] for row in first["evidence"]], ["EV-ANCHOR"])
        self.assertEqual(first["candidates"][0]["evidence_ids"], ["EV-ANCHOR"])
        self.assertEqual(visible_case_ids(first)["candidate"], {"CL-HIGH"})
        self.assertEqual(visible_case_ids(first)["evidence"], {"EV-ANCHOR"})
        json.dumps(first)

        rendered = json.dumps(first, sort_keys=True)
        for secret in (
            "QUERY-SECRET", "OPEN-QUERY-SECRET", "RAW-SECRET", "PROVENANCE-SECRET",
            "TOP-LEVEL-SECRET", "DO-NOT-EXPOSE", "COVERAGE-SECRET", "NOVELTY-SECRET",
        ):
            self.assertNotIn(secret, rendered)

    def test_projects_exact_search_path_gap_and_novelty_context_without_query_bodies(self):
        from romulus.investigation.casefile import build_case_file

        case = build_case_file(_state())

        self.assertEqual(case["version"], 1)
        self.assertEqual(case["mission"]["hunt_id"], "HUNT-CASEFILE")
        self.assertEqual(case["mission"]["mode"], "undirected")
        completed = case["completed_searches"][0]
        self.assertEqual(completed["task_id"], "ST-DONE")
        self.assertEqual(completed["intent"], "Validate the observed process sequence")
        self.assertEqual(completed["matched_total"], 12)
        self.assertEqual(completed["total_relation"], "gte")
        self.assertEqual(completed["sampling"]["strategy"], "rank_stratified")
        self.assertNotIn("query_spec", completed)

        self.assertEqual(case["path_fragments"][0]["path_id"], "PATH-1")
        self.assertEqual(case["path_fragments"][0]["steps"][0]["evidence_ids"], ["EV-ANCHOR"])
        self.assertEqual(case["unresolved_follow_ups"][0]["follow_up_id"], "FU-HIGH")
        self.assertTrue(any(gap.get("reason") == "source_unavailable" for gap in case["coverage_gaps"]))
        self.assertTrue(any(gap.get("hypothesis_id") == "H-OPEN" for gap in case["coverage_gaps"]))
        self.assertEqual(case["novelty"]["stage"], "reasoning")
        self.assertEqual(case["novelty"]["signals"], {"new_evidence": 0, "new_paths": 0})
        self.assertNotIn("private_note", case["novelty"])

    def test_bounds_sections_and_normalizes_legacy_follow_up_shape(self):
        from romulus.investigation.casefile import build_case_file

        state = _state()
        state["candidate_leads"][1].pop("follow_ups")
        state["candidate_leads"][1]["follow_up"] = ["Review the adjacent account activity."]
        for index in range(10):
            evidence_id = f"EV-EXTRA-{index:02d}"
            state["host"].append({
                "evidence_id": evidence_id,
                "source": "elasticsearch",
                "observed_at": f"2022-01-24T04:{index:02d}:00Z",
                "observation": f"extra {index}",
            })
            state["search_outcomes"].append({
                "task_id": f"ST-EXTRA-{index:02d}",
                "source": "elasticsearch",
                "status": "completed",
                "returned_total": index,
                "matched_total": index,
            })

        case = build_case_file(
            state,
            evidence_limit=3,
            candidate_limit=2,
            hypothesis_limit=1,
            timeline_limit=2,
            outcome_limit=2,
        )

        self.assertLessEqual(len(case["evidence"]), 3)
        self.assertLessEqual(len(case["candidates"]), 2)
        self.assertLessEqual(len(case["hypotheses"]), 1)
        self.assertLessEqual(len(case["timeline"]), 2)
        self.assertLessEqual(len(case["completed_searches"]), 2)
        follow_up = next(row for row in case["unresolved_follow_ups"] if row["candidate_id"] == "CL-HIGH")
        self.assertEqual(follow_up["intent"], "Review the adjacent account activity.")
        self.assertTrue(follow_up["follow_up_id"].startswith("LEGACY-FU-"))

    def test_visible_ids_include_all_grounding_namespaces(self):
        from romulus.investigation.casefile import visible_case_ids

        visible = visible_case_ids({
            "candidates": [{"candidate_id": "CL-1", "evidence_ids": ["EV-1"], "proposal_id": "P-1"}],
            "hypotheses": [{"hypothesis_id": "H-1", "candidate_id": "CL-1"}],
            "evidence": [{"evidence_id": "EV-1"}],
            "completed_searches": [{"task_id": "ST-1", "follow_up_ids": ["FU-1"]}],
            "unresolved_follow_ups": [{"follow_up_id": "FU-2", "task_ids": ["ST-2"]}],
            "path_fragments": [],
        })

        self.assertEqual(visible, {
            "candidate": {"CL-1"},
            "evidence": {"EV-1"},
            "hypothesis": {"H-1"},
            "follow_up": {"FU-1", "FU-2"},
            "task": {"ST-1", "ST-2"},
            "proposal": {"P-1"},
        })


if __name__ == "__main__":
    unittest.main()
