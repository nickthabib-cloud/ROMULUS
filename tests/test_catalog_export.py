"""JSON-serializable public catalog export schema."""

from __future__ import annotations

import json

from romulus.catalog import build_catalog, export


def test_catalog_export_has_the_public_ui_schema_and_round_trips_json():
    document = export()

    assert set(document) == {
        "schema_version",
        "attack_version",
        "pack_version",
        "coverage_strength_legend",
        "technique_strength_policy",
        "rules",
        "techniques",
        "tactics",
        "telemetry",
        "gaps",
        "metadata_issues",
    }
    assert document["schema_version"] == 1
    assert document["attack_version"] == "20.0"
    assert document["pack_version"] == "pack@21"
    assert json.loads(json.dumps(document)) == document


def test_catalog_export_contains_sorted_rules_techniques_strengths_and_telemetry():
    document = export(build_catalog())
    rules = document["rules"]
    techniques = document["techniques"]
    telemetry = document["telemetry"]

    assert [item["id"] for item in rules] == sorted(item["id"] for item in rules)
    assert [item["id"] for item in techniques] == sorted(item["id"] for item in techniques)
    assert [item["family"] for item in telemetry] == sorted(item["family"] for item in telemetry)
    guessing = next(item for item in techniques if item["id"] == "T1110.001")
    assert guessing["strength"] == "positive-only"
    assert "host.ssh_password_guessing" in guessing["rule_ids"]
    assert guessing["telemetry_families"] == ["auth"]
    assert set(guessing) >= {
        "data_sources",
        "data_components",
        "platforms",
        "tactics",
        "status",
    }
    lateral = next(item for item in rules if item["id"] == "context.lateral_movement")
    assert lateral["required_by_family"] == {
        "net_socket": ["destination.ip", "destination.port"],
        "process_exec": ["process.argv", "process.executable"],
    }
    net_socket = next(item for item in telemetry if item["family"] == "net_socket")
    assert {"destination.ip", "destination.port"} <= set(net_socket["required_fields"])
    fingerprint = next(item for item in rules if item["id"] == "net.rare_client_fingerprint")
    assert fingerprint["coverage_strength"] == "context-only"
    assert "lead-capped" not in {item["coverage_strength"] for item in rules}


def test_catalog_export_explains_strength_and_labels_each_covering_rule():
    document = export()
    web_protocols = next(item for item in document["techniques"] if item["id"] == "T1071.001")

    assert document["technique_strength_policy"] == (
        "A technique's strength is the strongest strength among its active covering rules."
    )
    assert document["coverage_strength_legend"]["negative-capable"] == (
        "A covering rule can report a complete negative for its own predicate when runtime "
        "coverage is complete; this never means the ATT&CK technique is absent."
    )
    assert document["coverage_strength_legend"]["context-only"] == (
        "A covering rule can provide investigation context, but it cannot support a complete "
        "negative."
    )
    assert web_protocols["covering_rules"] == [
        {"rule_id": "net.rare_client_fingerprint", "strength": "context-only"}
    ]


def test_catalog_export_marks_every_uncovered_technique_as_a_gap():
    document = export()
    expected = [item["id"] for item in document["techniques"] if item["status"] == "not covered"]

    assert [item["id"] for item in document["gaps"]] == expected
    assert expected
    assert all(item["status"] == "not covered" for item in document["gaps"])
    assert all("telemetry" in item for item in document["gaps"])


def test_catalog_export_is_byte_deterministic_and_reports_metadata_issues():
    first = json.dumps(export(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(export(), sort_keys=True, separators=(",", ":"))
    issues = export()["metadata_issues"]

    assert first == second
    assert issues["missing_attack_ids"] == ["ioc.indicator_match", "net.suricata_alert_stack"]
    assert issues["invalid_attack_ids"] == [
        {
            "rule_id": "host.firewall_rule_change_command",
            "attack_id": "T0815",
            "reason": "ATT&CK for ICS id (not in the Enterprise bundle)",
            "replacement_id": None,
        },
        {
            "rule_id": "host.firewall_rule_change_command",
            "attack_id": "T1562.004",
            "reason": "revoked",
            "replacement_id": "T1686",
        },
    ]
