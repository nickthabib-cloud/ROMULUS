import unittest


def event(identifier, minute, **fields):
    raw = {"@timestamp": f"2026-10-15T12:{minute:02d}:00Z"}
    for path, value in fields.items():
        current = raw
        parts = path.split("__")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value
    return {
        "evidence_id": identifier,
        "observed_at": raw["@timestamp"],
        "source": "elasticsearch",
        "source_family": "network" if "source" in fields or "destination" in fields else "host",
        "raw": raw,
    }


def rule(identifier, primitive, **execution):
    return {
        "id": identifier,
        "title": identifier,
        "base_score": 75,
        "specificity": 80,
        "priority": "high",
        "attack_techniques": ["T1046"],
        "follow_up": ["Review aggregate."],
        "benign_explanations": ["Authorized activity."],
        "execution": {"status": "executable", "execution_kind": "aggregate",
                      "primitive": primitive, "window_minutes": 60,
                      "group_by": [], "sample_min": 1, **execution},
    }


class AggregateEvaluationTests(unittest.TestCase):
    def test_count_distinct_count_fanout_rate_and_volume(self):
        from romulus.intelligence.aggregate_analytics import evaluate_aggregates

        evidence = [
            event("E1", 0, source__ip="10.0.0.1", destination__ip="192.0.2.1", network__bytes=40),
            event("E2", 1, source__ip="10.0.0.1", destination__ip="192.0.2.2", network__bytes=60),
            event("E3", 2, source__ip="10.0.0.1", destination__ip="192.0.2.2", network__bytes=50),
        ]
        definitions = [
            rule("count", "count", threshold={"operator": "gte", "value": 3}),
            rule("distinct", "distinct_count", distinct_field="destination.ip",
                 threshold={"operator": "gte", "value": 2}),
            rule("fanout", "fanout", group_by=["source.ip"], distinct_field="destination.ip",
                 threshold={"operator": "gte", "value": 2}),
            rule("rate", "rate", threshold={"operator": "gte", "value": 0.05}),
            rule("volume", "volume", measure_field="network.bytes",
                 threshold={"operator": "gte", "value": 150}),
        ]

        matches, _ = evaluate_aggregates(evidence, definitions, None)

        self.assertEqual({row["analytic_id"] for row in matches}, {"count", "distinct", "fanout", "rate", "volume"})

    def test_transition_ratio_duration_and_periodicity(self):
        from romulus.intelligence.aggregate_analytics import evaluate_aggregates

        evidence = [
            event("E1", 0, user__name="alice", event__outcome="failure", source__bytes=90, destination__bytes=10),
            event("E2", 10, user__name="alice", event__outcome="failure", source__bytes=90, destination__bytes=10),
            event("E3", 20, user__name="alice", event__outcome="success", source__bytes=90, destination__bytes=10),
            event("E4", 30, user__name="alice", event__outcome="success", source__bytes=90, destination__bytes=10),
        ]
        definitions = [
            rule("transition", "transition", group_by=["user.name"],
                 from_filter={"field": "event.outcome", "operator": "equals", "values": ["failure"]},
                 to_filter={"field": "event.outcome", "operator": "equals", "values": ["success"]},
                 from_count=2, threshold={"operator": "gte", "value": 1}),
            rule("ratio", "ratio", numerator_field="source.bytes", denominator_field="destination.bytes",
                 threshold={"operator": "gte", "value": 8}),
            rule("duration", "duration", threshold={"operator": "gte", "value": 1800}),
            rule("periodicity", "periodicity", sample_min=4,
                 threshold={"operator": "lte", "value": 0.01}),
        ]

        matches, _ = evaluate_aggregates(evidence, definitions, None)

        self.assertEqual({row["analytic_id"] for row in matches}, {"transition", "ratio", "duration", "periodicity"})

    def test_truncation_makes_nonmatch_partial(self):
        from romulus.intelligence.aggregate_analytics import evaluate_aggregates

        definition = rule("needs-five", "count", threshold={"operator": "gte", "value": 5})
        outcomes = [{"source_family": "host", "status": "partial", "capped": True}]

        matches, coverage = evaluate_aggregates(
            [event("E1", 0), event("E2", 1)], [definition], outcomes
        )

        self.assertEqual(matches, [])
        self.assertEqual(coverage["by_rule"]["needs-five"]["state"], "partial")

    def test_pack_reconciles_all_206_aggregate_records(self):
        from romulus.intelligence.behavior_packs import load_behavior_packs

        records = load_behavior_packs()["aggregates"]["records"]

        self.assertEqual(len(records), 206)
        self.assertTrue(all(row.get("execution", {}).get("status") in {"executable", "reference_only"}
                            for row in records))
        self.assertTrue(any(row["execution"]["status"] == "executable" for row in records))


if __name__ == "__main__":
    unittest.main()
