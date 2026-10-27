"""Public ATT&CK and playbook catalog contracts."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import ClassVar

import pytest

import romulus.catalog.build as catalog_build
from romulus.catalog import (
    CoverageStrength,
    build_catalog,
    load_attack_bundle,
    strength_for_rule,
)
from romulus.detect.registry import ALL_PLAYBOOKS, PACK_VERSION

ROOT = Path(__file__).resolve().parents[1]
ATTACK_BUNDLE = ROOT / "content" / "attack" / "enterprise-attack-20.0.json.gz"


def test_vendored_attack_bundle_loads_the_pinned_enterprise_release():
    attack = load_attack_bundle(ATTACK_BUNDLE)

    active = [item for item in attack.techniques if not item.revoked and not item.deprecated]
    assert attack.version == "20.0"
    assert len(attack.tactics) == 15
    assert len([item for item in active if not item.is_subtechnique]) == 227
    assert len([item for item in active if item.is_subtechnique]) == 479
    assert attack.technique("T1055.011").parent_id == "T1055"
    assert attack.technique("T1055.011").platforms == ("Windows",)
    assert attack.technique("T1055.011").tactics == ("privilege-escalation", "stealth")
    assert attack.replacement("T1562.004") == "T1686"


def test_attack_loader_enforces_its_uncompressed_byte_bound(tmp_path):
    path = tmp_path / "oversized.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"type": "bundle", "objects": [], "padding": "x" * 128}, handle)

    with pytest.raises(ValueError, match="uncompressed byte limit"):
        load_attack_bundle(path, max_uncompressed_bytes=64)


@pytest.mark.parametrize(
    ("kind", "lane", "assures_negative", "expected"),
    [
        ("direct", "high", True, CoverageStrength.FULL_SEARCH),
        ("aggregate", "lead", False, CoverageStrength.POSITIVE_ONLY),
        ("aggregate", "context", True, CoverageStrength.CONTEXT_ONLY),
        ("context", "high", True, CoverageStrength.CONTEXT_ONLY),
    ],
)
def test_coverage_strength_comes_only_from_typed_rule_properties(
    kind, lane, assures_negative, expected
):
    class Rule:
        pass

    Rule.kind = kind
    Rule.lane = lane
    Rule.assures_negative = assures_negative
    assert strength_for_rule(Rule) is expected


def test_context_lane_cannot_overclaim_negative_capability():
    catalog = build_catalog()

    rule = catalog.rule("net.rare_client_fingerprint")
    assert rule.lane == "context"
    assert rule.assures_negative is True
    assert strength_for_rule(rule) is CoverageStrength.CONTEXT_ONLY
    assert catalog.coverage("T1071.001").strength is CoverageStrength.CONTEXT_ONLY


def test_catalog_exposes_only_strengths_supported_by_typed_metadata():
    assert tuple(strength.value for strength in CoverageStrength) == (
        "full-search",
        "positive-only",
        "context-only",
        "none",
    )


def test_catalog_loads_sorted_rule_metadata_and_reports_unmapped_active_rules():
    catalog = build_catalog()

    assert catalog.attack_version == "20.0"
    assert catalog.pack_version == PACK_VERSION
    assert tuple(rule.id for rule in catalog.rules) == tuple(sorted(rule.id for rule in catalog.rules))
    assert len(catalog.rules) == len(ALL_PLAYBOOKS)
    assert catalog.missing_attack_ids == ("ioc.indicator_match", "net.suricata_alert_stack")
    assert [
        (issue.rule_id, issue.attack_id, issue.reason, issue.replacement_id)
        for issue in catalog.invalid_attack_ids
    ] == [
        (
            "host.firewall_rule_change_command",
            "T0815",
            "ATT&CK for ICS id (not in the Enterprise bundle)",
            None,
        ),
        ("host.firewall_rule_change_command", "T1562.004", "revoked", "T1686"),
    ]
    ssh = catalog.rule("host.ssh_password_guessing")
    assert ssh.kind == "aggregate"
    assert ssh.families == ("auth",)
    assert ssh.positive_only_reason
    assert ssh.telemetry
    assert ssh.attack_ids == ("T1110.001",)


def test_catalog_preserves_required_fields_declared_per_event_family():
    rule = build_catalog().rule("context.lateral_movement")

    assert rule.required_fields == ()
    assert dict(rule.required_by_family) == {
        "net_socket": ("destination.ip", "destination.port"),
        "process_exec": ("process.argv", "process.executable"),
    }


def test_public_catalog_ignores_runtime_indicator_directory(tmp_path):
    malformed = tmp_path / "private.yaml"
    malformed.write_text("not: [valid", encoding="utf-8")
    expected_version = build_catalog().rule("ioc.indicator_match").version
    code = (
        "import json; "
        "from romulus.catalog import build_catalog; "
        "print(json.dumps(build_catalog().rule('ioc.indicator_match').version))"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    env["ROMULUS_INDICATOR_DIR"] = str(tmp_path)

    completed = subprocess.run(
        [sys.executable, "-B", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == expected_version


def test_build_catalog_does_not_mutate_process_indicator_environment(monkeypatch, tmp_path):
    class TrackingEnvironment(dict):
        def __init__(self, values):
            super().__init__(values)
            self.popped: list[str] = []

        def pop(self, key, *default):
            self.popped.append(key)
            return super().pop(key, *default)

    tracking = TrackingEnvironment(os.environ)
    tracking["ROMULUS_INDICATOR_DIR"] = str(tmp_path)
    before = dict(tracking)
    monkeypatch.setattr(catalog_build.os, "environ", tracking)

    build_catalog()

    assert dict(tracking) == before
    assert "ROMULUS_INDICATOR_DIR" not in tracking.popped


def test_catalog_maps_rules_to_techniques_and_tactic_rollups_deterministically():
    first = build_catalog()
    second = build_catalog()

    guessing = first.coverage("T1110.001")
    assert "host.ssh_password_guessing" in guessing.rule_ids
    assert guessing.strength is CoverageStrength.POSITIVE_ONLY
    assert guessing.telemetry_families == ("auth",)
    assert first == second
    assert tuple(item.technique.id for item in first.coverage_by_technique) == tuple(
        sorted(item.technique.id for item in first.coverage_by_technique)
    )
    credential_access = first.tactic("credential-access")
    assert credential_access.total > 0
    assert sum(credential_access.strength_counts.values()) == credential_access.total


def test_catalog_rejects_unknown_revoked_and_deprecated_rule_mappings():
    attack = load_attack_bundle(ATTACK_BUNDLE)

    class UnknownRule:
        id = "test.unknown"
        version = "1"
        title = "Unknown mapping"
        kind = "direct"
        lane = "lead"
        severity = "low"
        assures_negative = True
        positive_only_reason = ""
        families = ("process_exec",)
        required_fields = ()
        attack = ("T999999",)
        card: ClassVar[dict] = {}

    with pytest.raises(ValueError, match=r"test\.unknown.*T999999"):
        build_catalog(attack=attack, playbooks=(UnknownRule,), strict=True)

    retired = next(item for item in attack.techniques if item.revoked or item.deprecated)
    RetiredRule = type("RetiredRule", (UnknownRule,), {"id": "test.retired", "attack": (retired.id,)})
    with pytest.raises(ValueError, match=retired.id):
        build_catalog(attack=attack, playbooks=(RetiredRule,), strict=True)


def test_attack_knowledge_retains_revoked_and_deprecated_markers():
    attack = load_attack_bundle(ATTACK_BUNDLE)
    retired = next(item for item in attack.techniques if item.revoked or item.deprecated)

    changed = replace(retired, name="still typed")
    assert changed.revoked or changed.deprecated
