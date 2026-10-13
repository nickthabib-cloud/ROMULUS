import copy
import unittest


def _case_file():
    return {
        "version": 1,
        "mission": {"hunt_id": "HUNT-REASONING", "mode": "undirected"},
        "candidates": [
            {
                "candidate_id": "CL-ONE",
                "title": "Observed service-account shell sequence",
                "evidence_ids": ["EV-ONE", "EV-TWO"],
                "assets": ["web-01"],
                "attack_techniques": ["T1059.004"],
                "benign_explanations": ["Authorized maintenance"],
                "follow_ups": [{"follow_up_id": "FU-ONE", "status": "pending"}],
            },
            {
                "candidate_id": "CL-TWO",
                "title": "Observed remote service activity",
                "evidence_ids": ["EV-OTHER"],
                "assets": ["db-01"],
                "attack_techniques": ["T1021.004"],
                "benign_explanations": ["Expected administration"],
                "follow_ups": [],
            },
        ],
        "hypotheses": [{
            "hypothesis_id": "H-BASE",
            "candidate_id": "CL-ONE",
            "technique_id": "T1059.004",
            "status": "inconclusive",
            "evidence_ids": ["EV-ONE"],
        }],
        "evidence": [
            {
                "evidence_id": "EV-ONE",
                "source": "elasticsearch",
                "asset": "web-01",
                "observed_at": "2022-04-01T10:00:00Z",
                "observation": "A service account launched a shell.",
                "raw": {"process.name": "bash", "source.ip": "192.0.2.10"},
            },
            {
                "evidence_id": "EV-TWO",
                "source": "arkime",
                "asset": "web-01",
                "observed_at": "2022-04-01T10:02:00Z",
                "observation": "The host created an adjacent outbound session.",
                "raw": {"destination.ip": "198.51.100.20"},
            },
            {
                "evidence_id": "EV-OTHER",
                "source": "arkime",
                "asset": "db-01",
                "observed_at": "2022-04-01T11:00:00Z",
                "observation": "An unrelated remote service session was observed.",
                "raw": {"source.ip": "203.0.113.5"},
            },
        ],
        "completed_searches": [],
        "unresolved_follow_ups": [{
            "candidate_id": "CL-ONE", "follow_up_id": "FU-ONE", "status": "pending"}],
        "path_fragments": [],
        "source_status": {"health": {"host": True, "network": True}},
        "coverage_gaps": [],
        "novelty": {},
    }


def _hypothesis(proposal_id="P-HYP", **updates):
    value = {
        "proposal_id": proposal_id,
        "candidate_id": "CL-ONE",
        "evidence_ids": ["EV-ONE", "EV-TWO"],
        "title": "The observed shell may have initiated the adjacent session",
        "technique_id": "T1059.004",
        "explanation": "The cited shell and session form a testable competing explanation.",
        "expected_host": ["A shell child process or related command near the anchor"],
        "expected_network": ["A session attributable to the cited host near the anchor"],
        "falsifying_observations": ["The session belongs to an unrelated approved process"],
        "benign_explanations": ["Authorized maintenance by the service owner"],
        "analytic_goal": "Determine whether the observed shell explains the adjacent connection.",
    }
    value.update(updates)
    return value


def _search(proposal_id="P-SEARCH", hypothesis_ref="P-HYP", **updates):
    value = {
        "proposal_id": proposal_id,
        "source": "elasticsearch",
        "hypothesis_ref": hypothesis_ref,
        "intent": "Search backward for the parent and initiating account.",
        "direction": "backward",
        "discriminating_goal": "Distinguish interactive maintenance from unexpected shell execution.",
        "candidate_id": "CL-ONE",
        "follow_up_id": "FU-ONE",
        "terms": ["bash"],
        "fields": ["process.name"],
        "ips": [],
        "hostnames": ["web-01"],
        "ports": [],
        "protocols": [],
        "event_codes": [],
        "index_class": "host",
        "anchor_evidence_ids": ["EV-ONE"],
        "native_query_language": "none",
        "native_query": "",
    }
    value.update(updates)
    return value


def _investigator(hypotheses=None, searches=None, assessments=None, findings=None):
    return {
        "assessments": assessments or [],
        "new_hypotheses": hypotheses or [],
        "searches": searches or [],
        "findings": findings or [],
        "summary": "Structured investigator theory, not an observed fact.",
    }


def _critic(*proposal_ids, decisions=None):
    decisions = decisions or {}
    return {"reviews": [{
        "proposal_id": proposal_id,
        "decision": decisions.get(proposal_id, ("accept", []))[0],
        "issue_codes": decisions.get(proposal_id, ("accept", []))[1],
        "rationale": "The structured proposal is grounded." if decisions.get(proposal_id, ("accept", []))[0] == "accept"
            else "The proposal is not admissible.",
    } for proposal_id in proposal_ids]}


def _rejection_reasons(result, proposal_id):
    reasons = set()
    for row in result["rejections"]:
        if row.get("proposal_id") == proposal_id:
            reasons.update(row.get("reason_codes", []))
    return reasons


class ReasoningAdmissionTests(unittest.TestCase):
    def test_existing_hypothesis_search_cannot_borrow_another_candidate_or_unseen_entity(self):
        from romulus.investigation.reasoning import admit_reasoning

        borrowed = _search("P-BORROW", "H-BASE", candidate_id="", follow_up_id="",
            anchor_evidence_ids=["EV-OTHER"], ips=["203.0.113.5"], hostnames=[])
        invented = _search("P-INVENT", "H-BASE", follow_up_id="",
            ips=["198.51.100.99"], hostnames=[])

        result = admit_reasoning(_case_file(), _investigator(searches=[borrowed, invented]),
            _critic("P-BORROW", "P-INVENT"), _case_file()["hypotheses"])

        self.assertEqual(result["searches"], [])
        borrowed_reasons = _rejection_reasons(result, "P-BORROW")
        self.assertTrue({"cross_candidate_citation", "search_anchor_mismatch"} & borrowed_reasons)
        self.assertIn("search_entity_mismatch", _rejection_reasons(result, "P-INVENT"))

    def test_mapped_hypothesis_cannot_publish_an_unmapped_finding(self):
        from romulus.investigation.reasoning import admit_reasoning

        case_file = _case_file()
        case_file["hypotheses"][0]["status"] = "supported"
        finding = {
            "proposal_id": "P-FIND", "hypothesis_id": "H-BASE",
            "title": "Shell activity", "technique_id": "unmapped",
            "observation": "Two records support review of the shell activity.",
            "interpretation": "The sequence remains an investigative lead.",
            "evidence_ids": ["EV-ONE", "EV-TWO"], "confidence": "moderate",
            "confidence_justification": "Two cited records.",
            "alternatives": ["Authorized maintenance"],
            "follow_up": ["Validate with the system owner."],
        }

        result = admit_reasoning(case_file, _investigator(findings=[finding]),
            _critic("P-FIND"), case_file["hypotheses"])

        self.assertEqual(result["findings"], [])
        self.assertIn("unsupported_attack_mapping", _rejection_reasons(result, "P-FIND"))

    def test_admits_critic_approved_competing_hypothesis_owned_by_visible_candidate(self):
        from romulus.investigation.reasoning import admit_reasoning

        case_file = _case_file()
        investigator = _investigator([_hypothesis()], [_search()])
        critic = _critic("P-HYP", "P-SEARCH")
        original = copy.deepcopy((case_file, investigator, critic))

        result = admit_reasoning(case_file, investigator, critic, case_file["hypotheses"])

        self.assertEqual((case_file, investigator, critic), original)
        self.assertEqual(len(result["new_hypotheses"]), 1)
        hypothesis = result["new_hypotheses"][0]
        self.assertTrue(hypothesis["hypothesis_id"].startswith("H-AI-"))
        self.assertEqual(hypothesis["basis"], "model_grounded_competing")
        self.assertEqual(hypothesis["basis_candidate_ids"], ["CL-ONE"])
        self.assertEqual(hypothesis["basis_evidence_ids"], ["EV-ONE", "EV-TWO"])
        self.assertIn("web-01", hypothesis["anchor_entities"])
        self.assertEqual(hypothesis["anchor_time_range"], {
            "start": "2022-04-01T10:00:00Z", "end": "2022-04-01T10:02:00Z"})
        self.assertNotIn("priority", hypothesis)
        self.assertEqual(result["searches"][0]["hypothesis_id"], hypothesis["hypothesis_id"])
        self.assertNotIn("hypothesis_ref", result["searches"][0])
        self.assertEqual(result["summary"]["new_hypotheses_admitted"], 1)
        self.assertEqual(result["rejections"], [])

    def test_rejects_unknown_unowned_or_cross_candidate_citations(self):
        from romulus.investigation.reasoning import admit_reasoning

        hypotheses = [
            _hypothesis("P-UNKNOWN", candidate_id="CL-MISSING"),
            _hypothesis("P-UNOWNED", evidence_ids=["EV-NOT-VISIBLE"]),
            _hypothesis("P-CROSS", evidence_ids=["EV-OTHER"]),
        ]
        searches = [
            _search("P-S-UNKNOWN", "P-UNKNOWN"),
            _search("P-S-UNOWNED", "P-UNOWNED"),
            _search("P-S-CROSS", "P-CROSS", anchor_evidence_ids=["EV-OTHER"]),
        ]
        ids = [row["proposal_id"] for row in hypotheses + searches]

        result = admit_reasoning(_case_file(), _investigator(hypotheses, searches),
            _critic(*ids), _case_file()["hypotheses"])

        self.assertEqual(result["new_hypotheses"], [])
        self.assertIn("unknown_candidate", _rejection_reasons(result, "P-UNKNOWN"))
        self.assertIn("unknown_evidence", _rejection_reasons(result, "P-UNOWNED"))
        self.assertIn("cross_candidate_citation", _rejection_reasons(result, "P-CROSS"))
        self.assertEqual(result["searches"], [])

    def test_rejects_unsupported_attack_mapping_and_missing_falsifier_or_benign_alternative(self):
        from romulus.investigation.reasoning import admit_reasoning

        hypotheses = [
            _hypothesis("P-MAPPING", technique_id="T9999"),
            _hypothesis("P-FALSIFIER", falsifying_observations=[]),
            _hypothesis("P-BENIGN", benign_explanations=[]),
            _hypothesis("P-TEXT", title="", explanation=""),
        ]
        searches = [_search(f"P-S-{index}", hypothesis["proposal_id"])
            for index, hypothesis in enumerate(hypotheses)]
        ids = [row["proposal_id"] for row in hypotheses + searches]

        result = admit_reasoning(_case_file(), _investigator(hypotheses, searches),
            _critic(*ids), _case_file()["hypotheses"])

        self.assertEqual(result["new_hypotheses"], [])
        self.assertIn("unsupported_attack_mapping", _rejection_reasons(result, "P-MAPPING"))
        self.assertIn("missing_falsifying_observation", _rejection_reasons(result, "P-FALSIFIER"))
        self.assertIn("missing_benign_alternative", _rejection_reasons(result, "P-BENIGN"))
        self.assertIn("missing_title", _rejection_reasons(result, "P-TEXT"))
        self.assertIn("missing_explanation", _rejection_reasons(result, "P-TEXT"))

    def test_rejects_unknown_critic_references_and_unreviewed_items(self):
        from romulus.investigation.reasoning import admit_reasoning

        result = admit_reasoning(
            _case_file(),
            _investigator([_hypothesis()], [_search()]),
            _critic("P-HYP", "P-GHOST"),
            _case_file()["hypotheses"],
        )

        self.assertEqual(result["new_hypotheses"], [])
        self.assertEqual(result["searches"], [])
        self.assertIn("unknown_critic_reference", _rejection_reasons(result, "P-GHOST"))
        self.assertIn("unreviewed", _rejection_reasons(result, "P-SEARCH"))
        self.assertIn("missing_approved_discriminating_search", _rejection_reasons(result, "P-HYP"))

    def test_requires_at_least_one_approved_discriminating_search_for_a_new_hypothesis(self):
        from romulus.investigation.reasoning import admit_reasoning

        critic = _critic("P-HYP", "P-SEARCH", decisions={
            "P-SEARCH": ("reject", ["missing_discriminating_search"]),
        })
        result = admit_reasoning(_case_file(), _investigator([_hypothesis()], [_search()]),
            critic, _case_file()["hypotheses"])

        self.assertEqual(result["new_hypotheses"], [])
        self.assertEqual(result["searches"], [])
        self.assertIn("missing_approved_discriminating_search", _rejection_reasons(result, "P-HYP"))
        self.assertIn("critic_rejected", _rejection_reasons(result, "P-SEARCH"))

    def test_deduplicates_stable_hypotheses_without_using_model_prose_as_fact(self):
        from romulus.investigation.reasoning import admit_reasoning

        first = admit_reasoning(_case_file(), _investigator([_hypothesis()], [_search()]),
            _critic("P-HYP", "P-SEARCH"), _case_file()["hypotheses"])
        existing = _case_file()["hypotheses"] + first["new_hypotheses"]
        rewritten = _hypothesis(
            title="Dramatic but structurally irrelevant prose",
            explanation="A different narrative must not change the structural identity.",
        )

        second = admit_reasoning(_case_file(), _investigator([rewritten], [_search()]),
            {"reviews": [
                {"proposal_id": "P-HYP", "decision": "accept", "issue_codes": [],
                    "rationale": "Completely different critic prose."},
                {"proposal_id": "P-SEARCH", "decision": "accept", "issue_codes": [],
                    "rationale": "Still structurally approved."},
            ]}, existing)

        self.assertEqual(second["new_hypotheses"], [])
        self.assertIn("duplicate_hypothesis", _rejection_reasons(second, "P-HYP"))
        self.assertEqual(second["searches"][0]["hypothesis_id"],
            first["new_hypotheses"][0]["hypothesis_id"])


if __name__ == "__main__":
    unittest.main()
