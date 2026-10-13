import unittest


def _state():
    return {
        "hunt_id": "HUNT-INDICATORS",
        "objective": "Broad evidence-led hunt.",
        "coverage": {
            "time_scope": "2022-01-24T03:00:00Z through 2022-01-24T05:00:00Z",
            "host": "available",
            "network": "partial",
        },
        "host": [{
            "evidence_id": "EV-WEB",
            "source": "elasticsearch",
            "asset": "web-01",
            "observed_at": "2022-01-24T03:57:38Z",
            "observation": "GET /wget returned 404 during directory enumeration by dirb.",
            "raw": {
                "http.request.method": "GET",
                "http.uri": "/wget",
                "http.status_code": 404,
                "user_agent.original": "dirb/2.22",
                "source.ip": "172.19.131.174",
                "destination.ip": "10.143.2.4",
            },
            "provenance": {
                "search_id": "ST-WEB",
                "index": "host-events",
                "document_id": "DOC-WEB",
                "path": "gather/attacker_0/logs/answer-revealing.log",
            },
            "ait": {
                "ground_truth_available": True,
                "ground_truth": {"labels": ["attacker", "dirb"], "rules": {"answer": ["rule"]}},
            },
        }],
        "network": [{
            "evidence_id": "EV-DNS-1",
            "source": "arkime",
            "asset": "share-01",
            "observed_at": "2022-01-24T04:02:25Z",
            "observation": "Long sequenced DNS label observed.",
            "raw": {
                "dns.qry.name": "3x6-.254-.abc-.quarterly.xlsx.transfer.example",
                "source.ip": "10.143.0.103",
                "destination.ip": "192.168.230.122",
                "destination.port": 53,
                "network.protocol": "dns",
            },
            "provenance": {"search_id": "ST-DNS-1", "session_id": "S-1"},
        }, {
            "evidence_id": "EV-DNS-2",
            "source": "tshark",
            "asset": "share-01",
            "observed_at": "2022-01-24T04:02:27Z",
            "observation": "The same DNS query was visible at a second sensor.",
            "raw": {
                "dns.qry.name": "3x6-.254-.abc-.quarterly.xlsx.transfer.example",
                "source.ip": "10.143.0.103",
                "destination.ip": "192.168.230.122",
                "destination.port": 53,
            },
            "provenance": {
                "search_id": "ST-DNS-2",
                "pcap": "/captures/scenario-answer-dnsteal.pcap",
            },
        }, {
            "evidence_id": "EV-UNOWNED",
            "source": "elasticsearch",
            "asset": "secret-host",
            "observed_at": "2022-01-24T04:03:00Z",
            "observation": "This record is not owned by a report item.",
            "raw": {"message": "SECRET-ANSWER"},
            "ait": {"ground_truth": {"labels": ["malicious"]}},
        }],
        "correlations": [{
            "correlation_id": "COR-DNS",
            "host_ref": "EV-DNS-1",
            "network_ref": "EV-DNS-2",
            "reason": "same normalized DNS query",
            "score": 0.95,
        }, {
            "correlation_id": "COR-UNOWNED",
            "host_ref": "EV-UNOWNED",
            "network_ref": "EV-DNS-1",
            "reason": "must not escape",
        }],
    }


def _items():
    return [{
        "item_id": "CL-DNS",
        "candidate_ids": ["CL-DNS"],
        "classification": "suspicious",
        "title": "Repeated encoded DNS label burst",
        "observation": "Several long DNS labels shared a suffix.",
        "why_it_matters": "The bounded pattern warrants analyst review.",
        "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
        "assets": ["share-01"],
        "first_observed": "2022-01-24T04:02:25Z",
        "last_observed": "2022-01-24T04:02:27Z",
        "investigation_status": "follow_up_exhausted",
        "follow_up_results": [],
        "benign_alternatives": ["Authorized DNS tunnel."],
        "coverage_gaps": ["Endpoint process attribution unavailable."],
        "recommended_actions": ["Identify the originating process and user."],
        "confidence": "moderate",
        "attack_techniques": ["T1071.004"],
    }, {
        "item_id": "CL-WEB",
        "candidate_ids": ["CL-WEB"],
        "classification": "suspicious",
        "title": "Download followed by an execution-oriented command",
        "observation": "A tool-like path appeared in an HTTP request.",
        "why_it_matters": "Requires validation.",
        "evidence_ids": ["EV-WEB"],
        "assets": ["web-01"],
        "first_observed": "2022-01-24T03:57:38Z",
        "last_observed": "2022-01-24T03:57:38Z",
        "investigation_status": "follow_up_exhausted",
        "follow_up_results": [],
        "benign_alternatives": ["Directory enumeration."],
        "coverage_gaps": [],
        "recommended_actions": ["Review adjacent web requests."],
        "confidence": "not assessed",
        "attack_techniques": ["T1105"],
    }]


class IndicatorCaseTests(unittest.TestCase):
    def test_case_owns_evidence_extracts_observables_and_scrubs_answers(self):
        from romulus.reporting.indicator_review import build_indicator_case

        case = build_indicator_case(_state(), _items())

        self.assertEqual({row["evidence_id"] for row in case["evidence"]}, {
            "EV-DNS-1", "EV-DNS-2", "EV-WEB",
        })
        rendered = repr(case).lower()
        self.assertNotIn("ground_truth", rendered)
        self.assertNotIn("answer-revealing", rendered)
        self.assertNotIn("scenario-answer", rendered)
        self.assertNotIn("secret-answer", rendered)
        observables = {
            (row["type"], row["value"])
            for evidence in case["evidence"]
            for row in evidence["observables"]
        }
        self.assertIn(("domain", "3x6-.254-.abc-.quarterly.xlsx.transfer.example"), observables)
        self.assertIn(("ip", "10.143.0.103"), observables)
        self.assertIn(("port", "53"), observables)
        self.assertIn(("url_path", "/wget"), observables)
        self.assertIn(("http_status", "404"), observables)
        self.assertEqual([row["relationship_id"] for row in case["relationships"]], ["COR-DNS"])


class IndicatorAdmissionTests(unittest.TestCase):
    def _case(self):
        from romulus.reporting.indicator_review import build_indicator_case
        return build_indicator_case(_state(), _items())

    def test_admission_resolves_canonical_artifacts_and_consolidates_duplicates(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        dns_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] in {"EV-DNS-1", "EV-DNS-2"}
            for row in evidence["observables"]
            if row["type"] in {"domain", "ip", "port"}
        ]
        second_sensor_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] == "EV-DNS-2"
            for row in evidence["observables"]
            if row["type"] in {"domain", "ip", "port"}
        ]
        proposal = {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"],
                "evidence_ids": ["EV-DNS-1", "EV-DNS-2"],
                "observable_ids": dns_observables,
                "relationship_ids": ["COR-DNS"],
                "title": "Sequenced encoded DNS activity",
                "assessment": "Repeated sequenced labels are consistent with an encoded DNS channel.",
                "limitations": ["Endpoint process attribution is unavailable."],
                "recommended_follow_ups": ["Identify the originating process and account."],
                "confidence": "high",
                "outcome": "suspected",
            }, {
                "item_ids": ["CL-DNS"],
                "evidence_ids": ["EV-DNS-2"],
                "observable_ids": second_sensor_observables,
                "relationship_ids": ["COR-DNS"],
                "title": "Duplicate sensor view",
                "assessment": "Second sensor view of the same activity.",
                "limitations": [],
                "recommended_follow_ups": [],
                "confidence": "moderate",
                "outcome": "suspected",
            }],
            "supporting_context": [],
            "likely_noise": [],
            "possible_activity_narrative": {
                "item_ids": ["CL-DNS"],
                "relationship_ids": ["COR-DNS"],
                "summary": "The observations may represent one bounded DNS activity cluster.",
                "limitations": ["Process attribution is unavailable."],
            },
            "recommended_follow_ups": ["Identify the process that generated the queries."],
        }

        admitted = admit_indicator_review(case, proposal)

        self.assertEqual(admitted["status"], "admitted")
        self.assertEqual(len(admitted["strong_indicators"]), 1)
        indicator = admitted["strong_indicators"][0]
        self.assertEqual(indicator["evidence_ids"], ["EV-DNS-1", "EV-DNS-2"])
        self.assertIn("3x6-.254-.abc-.quarterly.xlsx.transfer.example", {
            row["value"] for row in indicator["artifacts"]
        })
        self.assertEqual(indicator["assets"], ["share-01"])

    def test_unknown_selector_rejects_the_entire_proposal(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        rejected = admit_indicator_review(self._case(), {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"], "evidence_ids": ["EV-NOT-REAL"],
                "observable_ids": ["OB-NOT-REAL"], "relationship_ids": [],
                "title": "Invented indicator", "assessment": "Invented artifact evil.example.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "high", "outcome": "confirmed",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["strong_indicators"], [])
        self.assertIn("unknown_evidence_id", rejected["rejection_codes"])

    def test_http_404_path_probe_cannot_support_confirmed_download(self):
        from romulus.reporting.indicator_review import admit_indicator_review

        case = self._case()
        web_observables = [
            row["observable_id"] for evidence in case["evidence"]
            if evidence["evidence_id"] == "EV-WEB"
            for row in evidence["observables"]
        ]
        rejected = admit_indicator_review(case, {
            "strong_indicators": [{
                "item_ids": ["CL-WEB"], "evidence_ids": ["EV-WEB"],
                "observable_ids": web_observables, "relationship_ids": [],
                "title": "Successful payload download and execution",
                "assessment": "The payload was downloaded and executed.",
                "limitations": [], "recommended_follow_ups": [],
                "confidence": "high", "outcome": "confirmed",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        })

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("unsupported_confirmed_outcome", rejected["rejection_codes"])

    def test_deterministic_fallback_preserves_reportable_items_and_artifacts(self):
        from romulus.reporting.indicator_review import deterministic_indicator_review

        fallback = deterministic_indicator_review(self._case(), "model unavailable")

        self.assertEqual(fallback["status"], "fallback")
        self.assertEqual({row["item_ids"][0] for row in fallback["strong_indicators"]}, {
            "CL-DNS", "CL-WEB",
        })
        self.assertTrue(any(row["artifacts"] for row in fallback["strong_indicators"]))
        self.assertEqual(fallback["reason"], "model unavailable")

    def test_persisted_selectors_are_rejected_when_canonical_evidence_changes(self):
        from romulus.reporting.indicator_review import (
            admit_indicator_review, indicator_review_proposal,
        )

        case = self._case()
        dns_evidence = next(row for row in case["evidence"] if row["evidence_id"] == "EV-DNS-1")
        proposal = {
            "strong_indicators": [{
                "item_ids": ["CL-DNS"], "evidence_ids": ["EV-DNS-1"],
                "observable_ids": [row["observable_id"] for row in dns_evidence["observables"]],
                "relationship_ids": [], "title": "DNS indicator",
                "assessment": "Evidence-backed DNS activity.", "limitations": [],
                "recommended_follow_ups": [], "confidence": "moderate", "outcome": "suspected",
            }],
            "supporting_context": [], "likely_noise": [],
            "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
            "recommended_follow_ups": [],
        }
        stored = admit_indicator_review(case, proposal)
        stale_case = dict(case)
        stale_case["evidence"] = [row for row in case["evidence"] if row["evidence_id"] != "EV-DNS-1"]

        rejected = admit_indicator_review(stale_case, indicator_review_proposal(stored))

        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("unknown_evidence_id", rejected["rejection_codes"])


if __name__ == "__main__":
    unittest.main()
