import unittest


def _policy(
    classification="anomalous",
    *,
    singular=False,
    minimum=1,
    upgrade="independent_typed_entity_within_30m",
):
    return {
        "default_classification": classification,
        "single_record_reportable": singular,
        "minimum_owned_evidence": minimum,
        "required_context_roles": ["process.command_line"],
        "upgrade_rule": upgrade,
        "downgrade_rule": "explicit_benign_evidence_only",
        "policy_version": 1,
        "policy_reason": "Reviewed deterministic unit-test policy.",
    }


def _candidate(policy=None, **updates):
    value = {
        "candidate_id": "CL-1",
        "kind": "behavior",
        "priority_score": 100,
        "evidence_ids": ["EV-1"],
        "classification_policy": policy or _policy(),
        "classification": "anomalous",
        "classification_history": [],
        "matched_context_roles": ["process.command_line"],
        "disposition": "observed",
        "follow_ups": [],
        "finding_ids": [],
    }
    value.update(updates)
    return value


class ClassificationPolicyTests(unittest.TestCase):
    def test_reviewed_singular_behavior_is_suspicious_independent_of_score(self):
        from romulus.investigation.classification import apply_classification

        specific = _candidate(
            _policy("suspicious", singular=True, upgrade="none"),
            priority_score=10,
        )
        weak = _candidate(priority_score=100)

        self.assertEqual(apply_classification(specific)["classification"], "suspicious")
        self.assertEqual(apply_classification(weak)["classification"], "anomalous")

    def test_minimum_counts_distinct_owned_evidence_not_duplicate_references(self):
        from romulus.investigation.classification import apply_classification

        policy = _policy("suspicious", minimum=2, upgrade="none")
        duplicate = _candidate(policy, evidence_ids=["EV-1", "EV-1"])
        distinct = _candidate(policy, evidence_ids=["EV-1", "EV-2"])

        self.assertEqual(apply_classification(duplicate)["classification"], "anomalous")
        self.assertEqual(apply_classification(distinct)["classification"], "suspicious")

    def test_suspicious_policy_requires_its_singular_and_context_contract(self):
        from romulus.investigation.classification import apply_classification

        aggregate_only = _candidate(_policy("suspicious", singular=False, minimum=1, upgrade="none"))
        missing_context = _candidate(
            _policy("suspicious", singular=True, minimum=1, upgrade="none"),
            matched_context_roles=[],
        )

        self.assertEqual(apply_classification(aggregate_only)["classification"], "anomalous")
        self.assertEqual(apply_classification(missing_context)["classification"], "anomalous")

    def test_only_current_policy_authorized_relationship_can_upgrade_an_anomaly(self):
        from romulus.investigation.classification import apply_classification

        relationship = {
            "candidate_id": "CL-2",
            "shared_entity_type": "ip",
            "shared_entity": "192.0.2.5",
            "evidence_ids": ["EV-1", "EV-2"],
            "time_delta_seconds": 60,
        }
        related = _candidate(related_candidates=[relationship])
        count_only = _candidate(related_candidates=[])
        forbidden = _candidate(
            _policy(upgrade="none"), related_candidates=[relationship]
        )

        self.assertEqual(
            apply_classification(related, relationship_count=1)["classification"],
            "suspicious",
        )
        self.assertEqual(
            apply_classification(count_only, relationship_count=1)["classification"],
            "anomalous",
        )
        self.assertEqual(
            apply_classification(forbidden, relationship_count=1)["classification"],
            "anomalous",
        )

    def test_classification_history_is_auditable_and_idempotent(self):
        from romulus.investigation.classification import apply_classification

        relationship = {
            "candidate_id": "CL-2",
            "evidence_ids": ["EV-1", "EV-2"],
            "time_delta_seconds": 60,
        }
        first = apply_classification(
            _candidate(related_candidates=[relationship]), relationship_count=1
        )
        second = apply_classification(first, relationship_count=1)

        self.assertEqual(first["classification"], "suspicious")
        self.assertEqual(len(first["classification_history"]), 1)
        change = first["classification_history"][0]
        self.assertEqual(change["prior"], "anomalous")
        self.assertEqual(change["new"], "suspicious")
        self.assertEqual(change["rule"], "independent_typed_entity_within_30m")
        self.assertEqual(change["evidence_ids"], ["EV-1", "EV-2"])
        self.assertTrue(change["timestamp"].endswith("+00:00"))
        self.assertEqual(second["classification_history"], first["classification_history"])


class ClassificationMigrationAndLifecycleTests(unittest.TestCase):
    def test_findings_default_suspicious_and_cannot_accidentally_claim_malicious(self):
        from romulus.models import Finding

        finding = Finding(
            "F-1", "Evidence-backed lead", "suspected", "T1059", ["srv-01"],
            "Observed bounded behavior.", "Requires analyst review.", ["EV-1"],
            "moderate", "Deterministic behavior match.", [], [],
        )

        self.assertEqual(finding.classification, "suspicious")

    def test_legacy_candidates_fail_closed_and_never_infer_malicious(self):
        from romulus.investigation.classification import migrate_candidate

        high_score = migrate_candidate({"candidate_id": "CL-OLD", "priority_score": 100})
        trusted = migrate_candidate({
            "candidate_id": "CL-IOC",
            "kind": "trusted_indicator",
            "customer_visible": True,
        })

        self.assertEqual(high_score["classification"], "anomalous")
        self.assertEqual(trusted["classification"], "anomalous")
        self.assertFalse(high_score["customer_visible"])
        self.assertNotEqual(trusted["classification"], "malicious")
        self.assertEqual(trusted["classification_history"], [])

    def test_unprovenanced_or_non_indicator_malicious_state_fails_closed(self):
        from romulus.investigation.classification import migrate_candidate

        behavior = migrate_candidate({
            "candidate_id": "CL-BEHAVIOR", "kind": "behavior",
            "classification": "malicious", "evidence_ids": ["EV-1"],
        })
        incomplete_indicator = migrate_candidate({
            "candidate_id": "CL-IOC", "kind": "trusted_indicator",
            "classification": "malicious", "indicator_confidence": 95,
            "evidence_ids": ["EV-1"],
        })
        admitted = migrate_candidate({
            "candidate_id": "CL-ADMITTED", "kind": "trusted_indicator",
            "classification": "malicious", "indicator_confidence": 95,
            "indicator_source": "customer incident response",
            "indicator_type": "domain", "indicator_value": "evil.example",
            "indicator_match_type": "exact", "indicator_current_at_match": True,
            "indicator_catalog_version": "1.0.0",
            "indicator_created_at": "2026-01-01T00:00:00Z",
            "indicator_expires_at": "2027-01-01T00:00:00Z",
            "indicator_matched_at": "2026-10-12T00:00:00Z",
            "evidence_ids": ["EV-1"],
        })

        self.assertEqual(behavior["classification"], "anomalous")
        self.assertEqual(incomplete_indicator["classification"], "anomalous")
        self.assertEqual(admitted["classification"], "malicious")

    def test_persisted_malicious_indicator_requires_complete_current_catalog_record(self):
        from romulus.investigation.classification import migrate_candidate

        complete = {
            "candidate_id": "CL-IOC", "kind": "trusted_indicator",
            "classification": "malicious", "indicator_confidence": 95,
            "indicator_source": "customer incident response", "indicator_type": "domain",
            "indicator_value": "evil.example", "indicator_match_type": "exact",
            "indicator_current_at_match": True, "indicator_catalog_version": "1.0.0",
            "indicator_created_at": "2026-01-01T00:00:00Z",
            "indicator_expires_at": "2027-01-01T00:00:00Z",
            "indicator_matched_at": "2026-10-12T00:00:00Z", "evidence_ids": ["EV-1"],
        }
        incomplete = dict(complete); incomplete.pop("indicator_created_at")
        expired = dict(complete, indicator_expires_at="2026-01-02T00:00:00Z")

        self.assertEqual(migrate_candidate(complete)["classification"], "malicious")
        self.assertEqual(migrate_candidate(incomplete)["classification"], "anomalous")
        self.assertEqual(migrate_candidate(expired)["classification"], "anomalous")

    def test_lifecycle_is_independent_from_classification(self):
        from romulus.investigation.classification import refresh_investigation_status

        suspicious = _candidate(
            _policy("suspicious", singular=True, upgrade="none"),
            classification="suspicious",
        )
        scheduled = refresh_investigation_status(dict(
            suspicious,
            follow_ups=[{"status": "pending", "history": []}],
        ))
        exhausted = refresh_investigation_status(dict(
            suspicious,
            follow_ups=[{
                "status": "blocked",
                "history": [{"status": "failed", "task_id": "ST-1"}],
            }],
        ))
        resolved = refresh_investigation_status(dict(
            suspicious,
            finding_ids=["F-1"],
        ))
        dismissed = refresh_investigation_status(dict(
            suspicious,
            disposition="benign_likely",
        ))

        self.assertEqual(scheduled["investigation_status"], "investigating")
        self.assertEqual(exhausted["investigation_status"], "follow_up_exhausted")
        self.assertEqual(resolved["investigation_status"], "resolved")
        self.assertEqual(dismissed["investigation_status"], "dismissed")
        self.assertEqual(scheduled["classification"], "suspicious")
        self.assertEqual(exhausted["classification"], "suspicious")

    def test_reportable_and_unresolved_anomaly_selectors_use_both_dimensions(self):
        from romulus.investigation.classification import (
            reportable_candidates,
            unresolved_anomalous_candidates,
        )

        rows = [
            _candidate(classification="anomalous", investigation_status="new"),
            _candidate(classification="anomalous", investigation_status="resolved", candidate_id="CL-2"),
            _candidate(classification="suspicious", investigation_status="follow_up_exhausted", candidate_id="CL-3"),
            _candidate(
                classification="malicious", investigation_status="resolved", candidate_id="CL-4",
                kind="trusted_indicator", indicator_confidence=95,
                indicator_source="customer incident response", indicator_type="domain",
                indicator_value="evil.example", indicator_match_type="exact",
                indicator_current_at_match=True,
                indicator_catalog_version="1.0.0",
                indicator_created_at="2026-01-01T00:00:00Z",
                indicator_expires_at="2027-01-01T00:00:00Z",
                indicator_matched_at="2026-10-12T00:00:00Z",
            ),
            _candidate(classification="suspicious", investigation_status="dismissed", candidate_id="CL-5"),
        ]

        self.assertEqual(
            [row["candidate_id"] for row in reportable_candidates(rows)],
            ["CL-4", "CL-3"],
        )
        self.assertEqual(
            [row["candidate_id"] for row in unresolved_anomalous_candidates(rows)],
            ["CL-1"],
        )


if __name__ == "__main__":
    unittest.main()
